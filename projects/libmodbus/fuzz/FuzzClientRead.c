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

/* FuzzClientRead.c - Tests client-side read operations with valid MBAP headers
 * Exercises FC 0x01, 0x02, 0x03, 0x04 response parsing
 * Constructs valid MBAP headers to pass pre_check_confirmation() and
 * fuzzes the response payload data.
 *
 * For register reads (FC 0x03, 0x04), also exercises the data conversion
 * functions (modbus_get_float_*) that convert register values to floats.
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

/* Sinks for conversions to prevent optimization.
 * Separate elements ensure each call is preserved. */
static float g_float_sink[4];
static volatile int32_t g_int32_sink;
static volatile int64_t g_int64_sink;
static volatile int16_t g_int16_sink;

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

/* FC 0x01/0x02: Read Bits Response
 * Response: FC (1) + Byte Count (1) + Data (N)
 * Byte count = ceil(quantity / 8)
 */
static int build_read_bits_response(uint8_t *rsp, const uint8_t *req,
                                     const uint8_t *fuzz, size_t fuzz_len) {
    uint16_t quantity = (req[10] << 8) | req[11];
    if (quantity > 2000) quantity = 2000;  /* Modbus limit */
    if (quantity == 0) quantity = 1;

    int byte_count = (quantity + 7) / 8;
    build_mbap_header(rsp, req, 2 + byte_count);

    rsp[7] = req[7];  /* Echo FC */
    rsp[8] = byte_count;
    for (int i = 0; i < byte_count; i++) {
        rsp[9 + i] = (i < (int)fuzz_len) ? fuzz[i] : 0x00;
    }
    return 9 + byte_count;
}

/* FC 0x03/0x04: Read Registers Response
 * Response: FC (1) + Byte Count (1) + Data (N*2)
 * Byte count = quantity * 2
 */
static int build_read_registers_response(uint8_t *rsp, const uint8_t *req,
                                          const uint8_t *fuzz, size_t fuzz_len) {
    uint16_t quantity = (req[10] << 8) | req[11];
    if (quantity > 125) quantity = 125;  /* Modbus limit */
    if (quantity == 0) quantity = 1;

    int byte_count = quantity * 2;
    build_mbap_header(rsp, req, 2 + byte_count);

    rsp[7] = req[7];  /* Echo FC */
    rsp[8] = byte_count;
    for (int i = 0; i < byte_count; i++) {
        rsp[9 + i] = (i < (int)fuzz_len) ? fuzz[i] : 0xAA;
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
            case 0x01: /* Read Coils */
            case 0x02: /* Read Discrete Inputs */
                rsp_len = build_read_bits_response(response, request, fuzz, fuzz_len);
                break;
            case 0x03: /* Read Holding Registers */
            case 0x04: /* Read Input Registers */
                rsp_len = build_read_registers_response(response, request, fuzz, fuzz_len);
                break;
            default:
                /* Unknown FC - send exception response */
                build_mbap_header(response, request, 2);
                response[7] = fc | 0x80;
                response[8] = 0x01;  /* Illegal function */
                rsp_len = 9;
                break;
            }

            if (rsp_len > 0) send(client_fd, response, rsp_len, 0);
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

    /* Interpret fuzz data:
     * data[0] % 4 = operation selector (FC 0x01-0x04)
     * data[1] = quantity (clamped to Modbus limits)
     * data[2...] = response payload data
     */
    uint8_t op = data[0] % 4;
    uint16_t qty = (size > 1) ? data[1] : 10;

    /* Clamp quantity to Modbus limits */
    if (op < 2) {
        /* Bits: max 2000 */
        if (qty == 0) qty = 1;
        if (qty > 200) qty = 200;  /* Use smaller value for faster fuzzing */
    } else {
        /* Registers: max 125, min 2 for float conversion */
        if (qty < 2) qty = 2;
        if (qty > 125) qty = 125;
    }

    /* Pass fuzz data starting from byte 2 */
    g_fuzz_data = (size > 2) ? data + 2 : data;
    g_fuzz_size = (size > 2) ? size - 2 : 0;
    atomic_store(&g_state, 1);

    modbus_t *ctx = modbus_new_tcp("127.0.0.1", g_port);
    if (ctx == NULL) {
        while (atomic_load(&g_state) != 2) sched_yield();
        atomic_store(&g_state, 0);
        return 0;
    }

    /* Short timeouts for stability */
    modbus_set_response_timeout(ctx, 0, 10000);  /* 10ms */
    modbus_set_byte_timeout(ctx, 0, 5000);       /* 5ms */

    if (modbus_connect(ctx) == -1) {
        modbus_free(ctx);
        while (atomic_load(&g_state) != 2) sched_yield();
        atomic_store(&g_state, 0);
        return 0;
    }

    /* Allocate buffers for read results */
    uint8_t tab_bits[2000];
    uint16_t tab_regs[125];

    switch (op) {
    case 0: /* FC 0x01 - Read Coils */
        modbus_read_bits(ctx, UT_BITS_ADDRESS, qty, tab_bits);
        break;
    case 1: /* FC 0x02 - Read Discrete Inputs */
        modbus_read_input_bits(ctx, UT_INPUT_BITS_ADDRESS, qty, tab_bits);
        break;
    case 2: /* FC 0x03 - Read Holding Registers */
        {
            int nread = modbus_read_registers(ctx, UT_REGISTERS_ADDRESS, qty, tab_regs);
            if (nread >= 2) {
                /* Float conversions (modbus-data.c) — all byte order variants */
                g_float_sink[0] = modbus_get_float_abcd(tab_regs);
                g_float_sink[1] = modbus_get_float_dcba(tab_regs);
                g_float_sink[2] = modbus_get_float_badc(tab_regs);
                g_float_sink[3] = modbus_get_float_cdab(tab_regs);

                /* Round-trip through set_float — exercises vuln3 (aliasing) */
                uint16_t rt_dest[2];
                modbus_set_float_abcd(g_float_sink[0], rt_dest);
                modbus_set_float_dcba(g_float_sink[1], rt_dest);
                modbus_set_float_badc(g_float_sink[2], rt_dest);
                modbus_set_float_cdab(g_float_sink[3], rt_dest);

                /* Integer conversions on client-received data — vuln2 pattern */
                g_int32_sink = MODBUS_GET_INT32_FROM_INT16(tab_regs, 0);

                /* SET macro round-trip */
                uint16_t dest32[2];
                MODBUS_SET_INT32_TO_INT16(dest32, 0, g_int32_sink);
            }
            if (nread >= 4) {
                g_int64_sink = MODBUS_GET_INT64_FROM_INT16(tab_regs, 0);

                uint16_t dest64[4];
                MODBUS_SET_INT64_TO_INT16(dest64, 0, g_int64_sink);
            }
            /* INT16_FROM_INT8 on raw register bytes */
            if (nread >= 1) {
                g_int16_sink = MODBUS_GET_INT16_FROM_INT8(tab_regs, 0);
            }
        }
        break;
    case 3: /* FC 0x04 - Read Input Registers */
        {
            int nread = modbus_read_input_registers(ctx, UT_INPUT_REGISTERS_ADDRESS, qty, tab_regs);
            if (nread >= 2) {
                /* Float conversions (modbus-data.c) — all byte order variants */
                g_float_sink[0] = modbus_get_float_abcd(tab_regs);
                g_float_sink[1] = modbus_get_float_dcba(tab_regs);
                g_float_sink[2] = modbus_get_float_badc(tab_regs);
                g_float_sink[3] = modbus_get_float_cdab(tab_regs);

                /* Round-trip through set_float — exercises vuln3 (aliasing) */
                uint16_t rt_dest[2];
                modbus_set_float_abcd(g_float_sink[0], rt_dest);
                modbus_set_float_dcba(g_float_sink[1], rt_dest);
                modbus_set_float_badc(g_float_sink[2], rt_dest);
                modbus_set_float_cdab(g_float_sink[3], rt_dest);

                /* Integer conversions on client-received data — vuln2 pattern */
                g_int32_sink = MODBUS_GET_INT32_FROM_INT16(tab_regs, 0);

                uint16_t dest32[2];
                MODBUS_SET_INT32_TO_INT16(dest32, 0, g_int32_sink);
            }
            if (nread >= 4) {
                g_int64_sink = MODBUS_GET_INT64_FROM_INT16(tab_regs, 0);

                uint16_t dest64[4];
                MODBUS_SET_INT64_TO_INT16(dest64, 0, g_int64_sink);
            }
            if (nread >= 1) {
                g_int16_sink = MODBUS_GET_INT16_FROM_INT8(tab_regs, 0);
            }
        }
        break;
    }

    modbus_close(ctx);
    modbus_free(ctx);

    while (atomic_load(&g_state) != 2) sched_yield();
    atomic_store(&g_state, 0);
    return 0;
}
