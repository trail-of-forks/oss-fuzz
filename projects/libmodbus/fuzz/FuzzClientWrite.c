/* Copyright 2022 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* FuzzClientWrite.c - Tests client-side write operations
 * Exercises FC 0x05, 0x06, 0x0F, 0x10, 0x16, 0x17, 0x11
 * Uses stability patterns from FuzzServer.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <modbus.h>
#include "unit-test.h"

#define kMinInputLength 3
#define kMaxInputLength MODBUS_RTU_MAX_ADU_LENGTH

/* Persistent state */
static int g_listen_fd = -1;
static uint16_t g_port = 0;

/* Lock-free synchronization */
static pthread_t g_server_thread;
static atomic_int g_state = 0;      /* 0=idle, 1=work_ready, 2=work_done */
static atomic_int g_shutdown = 0;

/* Fuzzer input for current iteration */
static const uint8_t *g_fuzz_data = NULL;
static size_t g_fuzz_size = 0;

/* Response corruption flag (set from data[1] bit 0) */
static atomic_int g_corrupt = 0;

/* Build MBAP header that passes pre_check_confirmation() */
static void build_mbap_header(uint8_t *rsp, const uint8_t *req, int pdu_length) {
    rsp[0] = req[0];              /* Transaction ID high */
    rsp[1] = req[1];              /* Transaction ID low */
    rsp[2] = 0x00;                /* Protocol ID */
    rsp[3] = 0x00;
    int length = pdu_length + 1;  /* PDU + Unit ID */
    rsp[4] = (length >> 8) & 0xFF;
    rsp[5] = length & 0xFF;
    rsp[6] = req[6];              /* Unit ID */
}

/* FC 0x05/0x06: Write Single - echo entire request */
static int build_write_single_response(uint8_t *rsp, const uint8_t *req) {
    build_mbap_header(rsp, req, 5);
    rsp[7] = req[7];   /* FC */
    rsp[8] = req[8];   /* Address high - MUST match */
    rsp[9] = req[9];   /* Address low - MUST match */
    rsp[10] = req[10]; /* Value high - MUST match */
    rsp[11] = req[11]; /* Value low - MUST match */
    return 12;
}

/* FC 0x0F/0x10: Write Multiple - echo address and quantity */
static int build_write_multiple_response(uint8_t *rsp, const uint8_t *req) {
    build_mbap_header(rsp, req, 5);
    rsp[7] = req[7];   /* FC */
    rsp[8] = req[8];   /* Address high - MUST match */
    rsp[9] = req[9];   /* Address low - MUST match */
    rsp[10] = req[10]; /* Quantity high - MUST match */
    rsp[11] = req[11]; /* Quantity low - MUST match */
    return 12;
}

/* FC 0x16: Mask Write - echo all fields */
static int build_mask_write_response(uint8_t *rsp, const uint8_t *req) {
    build_mbap_header(rsp, req, 7);
    for (int i = 7; i < 14; i++) rsp[i] = req[i];
    return 14;
}

/* FC 0x17: Write/Read - response with fuzzer-controlled data */
static int build_write_and_read_response(uint8_t *rsp, const uint8_t *req,
                                          const uint8_t *fuzz, size_t fuzz_len) {
    uint16_t read_qty = (req[10] << 8) | req[11];
    if (read_qty > 125) read_qty = 125;
    if (read_qty == 0) read_qty = 1;

    int byte_count = read_qty * 2;
    build_mbap_header(rsp, req, 2 + byte_count);

    rsp[7] = 0x17;
    rsp[8] = byte_count;
    for (int i = 0; i < byte_count; i++) {
        rsp[9 + i] = (i < (int)fuzz_len) ? fuzz[i] : 0xAA;
    }
    return 9 + byte_count;
}

/* FC 0x11: Report Slave ID - variable length, fuzzer-controlled */
static int build_report_slave_id_response(uint8_t *rsp, const uint8_t *req,
                                           const uint8_t *fuzz, size_t fuzz_len) {
    int byte_count = (fuzz_len > 0) ? (fuzz[0] % 251 + 2) : 10;
    if (byte_count > 252) byte_count = 252;

    build_mbap_header(rsp, req, 2 + byte_count);
    rsp[7] = 0x11;
    rsp[8] = byte_count;
    for (int i = 0; i < byte_count; i++) {
        int idx = (i + 1) % (fuzz_len > 0 ? (int)fuzz_len : 1);
        rsp[9 + i] = (idx < (int)fuzz_len) ? fuzz[idx] : 0xBB;
    }
    return 9 + byte_count;
}

static void *server_thread(void *args) {
    (void)args;

    while (!atomic_load(&g_shutdown)) {
        while (atomic_load(&g_state) != 1) {
            if (atomic_load(&g_shutdown)) return NULL;
            sched_yield();
        }

        const uint8_t *fuzz = g_fuzz_data;
        size_t fuzz_len = g_fuzz_size;

        int client_fd = accept(g_listen_fd, NULL, NULL);
        if (client_fd < 0) {
            atomic_store(&g_state, 2);
            continue;
        }

        struct timeval tv = {.tv_sec = 0, .tv_usec = 50000};
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        uint8_t request[MODBUS_TCP_MAX_ADU_LENGTH];
        uint8_t response[MODBUS_TCP_MAX_ADU_LENGTH];

        int req_len = recv(client_fd, request, sizeof(request), 0);
        if (req_len >= 12) {
            uint8_t fc = request[7];
            int rsp_len = 0;

            switch (fc) {
            case 0x05: case 0x06:
                rsp_len = build_write_single_response(response, request);
                break;
            case 0x0F: case 0x10:
                rsp_len = build_write_multiple_response(response, request);
                break;
            case 0x16:
                rsp_len = build_mask_write_response(response, request);
                break;
            case 0x17:
                rsp_len = build_write_and_read_response(response, request, fuzz, fuzz_len);
                break;
            case 0x11:
                rsp_len = build_report_slave_id_response(response, request, fuzz, fuzz_len);
                break;
            default:
                build_mbap_header(response, request, 2);
                response[7] = fc | 0x80;
                response[8] = 0x01;
                rsp_len = 9;
                break;
            }

            /* Corrupt echo-type responses to exercise mismatch detection */
            if (rsp_len > 0) {
                int corrupt = atomic_load(&g_corrupt);
                if (corrupt && rsp_len > 9 &&
                    (fc == 0x05 || fc == 0x06 || fc == 0x0F ||
                     fc == 0x10 || fc == 0x16)) {
                    response[9] ^= 0xFF;
                }
                send(client_fd, response, rsp_len, 0);
            }
        }

        close(client_fd);
        atomic_store(&g_state, 2);
    }
    return NULL;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    signal(SIGPIPE, SIG_IGN);

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) return -1;

    int optval = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(0);

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(g_listen_fd);
        return -1;
    }

    socklen_t addr_len = sizeof(addr);
    getsockname(g_listen_fd, (struct sockaddr *)&addr, &addr_len);
    g_port = ntohs(addr.sin_port);

    listen(g_listen_fd, 5);

    struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
    setsockopt(g_listen_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    pthread_create(&g_server_thread, NULL, server_thread, NULL);
    return 0;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < kMinInputLength || size > kMaxInputLength) return 0;
    if (g_listen_fd < 0) return 0;

    g_fuzz_data = (size > 2) ? data + 2 : data;
    g_fuzz_size = (size > 2) ? size - 2 : 0;
    atomic_store(&g_corrupt, data[1] & 1);
    atomic_store(&g_state, 1);

    modbus_t *ctx = modbus_new_tcp("127.0.0.1", g_port);
    if (ctx == NULL) {
        while (atomic_load(&g_state) != 2) sched_yield();
        atomic_store(&g_state, 0);
        return 0;
    }

    /* CRITICAL: Short timeouts for stability */
    modbus_set_response_timeout(ctx, 0, 10000);  /* 10ms */
    modbus_set_byte_timeout(ctx, 0, 5000);       /* 5ms */

    if (modbus_connect(ctx) == -1) {
        modbus_free(ctx);
        while (atomic_load(&g_state) != 2) sched_yield();
        atomic_store(&g_state, 0);
        return 0;
    }

    /* Fill tab_regs and tab_bits from fuzzer data */
    uint8_t tab_bits[256];
    uint16_t tab_regs[128];
    const uint8_t *payload = (size > 2) ? data + 2 : data;
    size_t payload_len = (size > 2) ? size - 2 : 0;

    /* Fill tab_regs from fuzz data */
    for (int i = 0; i < 128; i++) {
        if (2 * i + 1 < (int)payload_len) {
            tab_regs[i] = (uint16_t)(payload[2*i] << 8 | payload[2*i + 1]);
        } else {
            tab_regs[i] = 0;
        }
    }

    /* Fill tab_bits from fuzz data */
    for (int i = 0; i < 256 && i < (int)payload_len; i++) {
        tab_bits[i] = payload[i] & 1;
    }
    memset(tab_bits + (payload_len < 256 ? payload_len : 256), 0,
           256 - (payload_len < 256 ? payload_len : 256));

    uint8_t op = data[0] % 7;

    switch (op) {
    case 0: /* FC 0x05 */
        modbus_write_bit(ctx, UT_BITS_ADDRESS, tab_bits[0]);
        break;
    case 1: /* FC 0x06 */
        modbus_write_register(ctx, UT_REGISTERS_ADDRESS, tab_regs[0]);
        break;
    case 2: /* FC 0x0F */
        modbus_write_bits(ctx, UT_BITS_ADDRESS, 10, tab_bits);
        break;
    case 3: /* FC 0x10 */
        modbus_write_registers(ctx, UT_REGISTERS_ADDRESS, 10, tab_regs);
        break;
    case 4: /* FC 0x16 */
        modbus_mask_write_register(ctx, UT_REGISTERS_ADDRESS, tab_regs[0], tab_regs[1]);
        break;
    case 5: /* FC 0x17 - HIGH VALUE: fuzzer-controlled response data */
        modbus_write_and_read_registers(ctx, UT_REGISTERS_ADDRESS, 5, tab_regs,
                                        UT_REGISTERS_ADDRESS, 5, tab_regs);
        break;
    case 6: /* FC 0x11 - HIGH VALUE: variable-length response */
        modbus_report_slave_id(ctx, 256, tab_bits);
        break;
    }

    modbus_close(ctx);
    modbus_free(ctx);

    while (atomic_load(&g_state) != 2) sched_yield();
    atomic_store(&g_state, 0);
    return 0;
}
