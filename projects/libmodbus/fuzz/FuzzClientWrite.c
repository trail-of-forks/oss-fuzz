/* Copyright 2024 Google LLC
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

/*
 * FuzzClientWrite - Tests client-side write operations
 * Extends FuzzClient.c to test write operations and additional read operations
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <modbus.h>
#include "unit-test.h"

#define kMinInputLength 9
#define kMaxInputLength MODBUS_RTU_MAX_ADU_LENGTH

struct Fuzzer {
    uint16_t port;
    uint64_t size;
    const uint8_t *buffer;
    pthread_t thread;
    int socket;
};
typedef struct Fuzzer Fuzzer;

int client(Fuzzer *fuzzer);

/* Returns 0 on success, -1 on failure */
int fuzzinit(Fuzzer *fuzzer) {
    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(server_addr);

    fuzzer->socket = socket(AF_INET, SOCK_STREAM, 0);
    if (fuzzer->socket < 0) {
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(0);  /* Use port 0 for dynamic assignment */
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    setsockopt(fuzzer->socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    if (bind(fuzzer->socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(fuzzer->socket);
        fuzzer->socket = -1;
        return -1;
    }

    /* Get the dynamically assigned port */
    if (getsockname(fuzzer->socket, (struct sockaddr *)&server_addr, &addr_len) < 0) {
        close(fuzzer->socket);
        fuzzer->socket = -1;
        return -1;
    }
    fuzzer->port = ntohs(server_addr.sin_port);

    if (listen(fuzzer->socket, 1) < 0) {
        close(fuzzer->socket);
        fuzzer->socket = -1;
        return -1;
    }

    return 0;
}

/*
 * Build a response that passes check_confirmation() but contains fuzzer data.
 * This ensures the vulnerable parsing loops are actually reached.
 */
static int build_valid_response(uint8_t *rsp, const uint8_t *req, int req_len,
                                 const uint8_t *fuzz_data, size_t fuzz_len) {
    if (req_len < 12) return -1;

    /* Extract request fields */
    uint16_t tx_id = (req[0] << 8) | req[1];
    uint8_t unit_id = req[6];
    uint8_t fc = req[7];
    uint16_t quantity = (req[10] << 8) | req[11];

    int rsp_len = 0;

    /* MBAP header - TxID must match for pre_check_confirmation */
    rsp[rsp_len++] = tx_id >> 8;
    rsp[rsp_len++] = tx_id & 0xFF;
    rsp[rsp_len++] = 0x00;  /* Protocol ID */
    rsp[rsp_len++] = 0x00;
    int len_pos = rsp_len;
    rsp[rsp_len++] = 0x00;  /* Length - fill later */
    rsp[rsp_len++] = 0x00;
    rsp[rsp_len++] = unit_id;

    /* Build PDU based on function code */
    switch (fc) {
        case 0x01:  /* Read Coils */
        case 0x02:  /* Read Discrete Inputs */
        {
            int byte_count = (quantity + 7) / 8;  /* Must match for check_confirmation */
            rsp[rsp_len++] = fc;
            rsp[rsp_len++] = byte_count;
            /* Fill with fuzzer data */
            for (int i = 0; i < byte_count; i++) {
                rsp[rsp_len++] = (i < (int)fuzz_len) ? fuzz_data[i] : 0xFF;
            }
            break;
        }
        case 0x03:  /* Read Holding Registers */
        case 0x04:  /* Read Input Registers */
        {
            int byte_count = quantity * 2;  /* Must match for check_confirmation */
            rsp[rsp_len++] = fc;
            rsp[rsp_len++] = byte_count;
            /* Fill registers with fuzzer data */
            for (int i = 0; i < byte_count; i++) {
                rsp[rsp_len++] = (i < (int)fuzz_len) ? fuzz_data[i] : 0xFF;
            }
            break;
        }
        case 0x05:  /* Write Single Coil */
        case 0x06:  /* Write Single Register */
        {
            /* Echo format - use fuzzer data for value */
            rsp[rsp_len++] = fc;
            rsp[rsp_len++] = req[8];   /* Address high */
            rsp[rsp_len++] = req[9];   /* Address low */
            rsp[rsp_len++] = (fuzz_len > 0) ? fuzz_data[0] : req[10];
            rsp[rsp_len++] = (fuzz_len > 1) ? fuzz_data[1] : req[11];
            break;
        }
        case 0x0F:  /* Write Multiple Coils */
        case 0x10:  /* Write Multiple Registers */
        {
            /* Echo address and quantity */
            rsp[rsp_len++] = fc;
            rsp[rsp_len++] = req[8];
            rsp[rsp_len++] = req[9];
            rsp[rsp_len++] = req[10];
            rsp[rsp_len++] = req[11];
            break;
        }
        case 0x17:  /* Write and Read Registers */
        {
            /* Read quantity is at offset 12-13 in request */
            uint16_t read_qty = (req[12] << 8) | req[13];
            int byte_count = read_qty * 2;
            rsp[rsp_len++] = fc;
            rsp[rsp_len++] = byte_count;
            for (int i = 0; i < byte_count; i++) {
                rsp[rsp_len++] = (i < (int)fuzz_len) ? fuzz_data[i] : 0xFF;
            }
            break;
        }
        case 0x11:  /* Report Slave ID - special: no request-based validation */
        {
            /* byte_count can be anything for FC 0x11 */
            int byte_count = (fuzz_len > 250) ? 250 : (fuzz_len > 2 ? fuzz_len : 2);
            rsp[rsp_len++] = fc;
            rsp[rsp_len++] = byte_count;
            for (int i = 0; i < byte_count; i++) {
                rsp[rsp_len++] = (i < (int)fuzz_len) ? fuzz_data[i] : 0xFF;
            }
            break;
        }
        case 0x16:  /* Mask Write Register */
        {
            rsp[rsp_len++] = fc;
            for (int i = 8; i < req_len && i < 14; i++) {
                rsp[rsp_len++] = req[i];
            }
            break;
        }
        default:
            /* Unknown FC - send exception */
            rsp[rsp_len++] = fc | 0x80;
            rsp[rsp_len++] = 0x01;
            break;
    }

    /* Fill MBAP length */
    int mbap_len = rsp_len - 6;
    rsp[len_pos] = mbap_len >> 8;
    rsp[len_pos + 1] = mbap_len & 0xFF;

    return rsp_len;
}

void *Server(void *args) {
    Fuzzer *fuzzer = (Fuzzer *)args;
    int client_fd;
    uint8_t request[MODBUS_TCP_MAX_ADU_LENGTH];
    uint8_t response[MODBUS_TCP_MAX_ADU_LENGTH];
    struct sockaddr_in clientAddr;
    uint32_t clientSZ = sizeof(clientAddr);

    client_fd = accept(fuzzer->socket, (struct sockaddr *)&clientAddr, &clientSZ);
    if (client_fd < 0) {
        pthread_exit(NULL);
    }

    /* Handle multiple requests */
    for (int i = 0; i < 3; i++) {
        int req_len = recv(client_fd, request, sizeof(request), 0);
        if (req_len <= 0) break;

        /* Build response that passes check_confirmation but has fuzzer data */
        int rsp_len = build_valid_response(response, request, req_len,
                                           fuzzer->buffer, fuzzer->size);
        if (rsp_len > 0) {
            send(client_fd, response, rsp_len, 0);
        }
    }

    shutdown(client_fd, SHUT_RDWR);
    close(client_fd);

    pthread_exit(NULL);
}

void clean(Fuzzer *fuzzer) {
    shutdown(fuzzer->socket, SHUT_RDWR);
    close(fuzzer->socket);
    free(fuzzer);
}

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < kMinInputLength || size > kMaxInputLength) {
        return 0;
    }

    Fuzzer *fuzzer = (Fuzzer *)malloc(sizeof(Fuzzer));
    if (!fuzzer) {
        return 0;
    }

    fuzzer->port = 0;  /* Will be set by fuzzinit */
    fuzzer->size = size - 1;  /* Reserve first byte for operation selector */
    fuzzer->buffer = data + 1;

    if (fuzzinit(fuzzer) < 0) {
        free(fuzzer);
        return 0;  /* Skip this input if socket setup fails */
    }

    pthread_create(&fuzzer->thread, NULL, Server, fuzzer);
    client(fuzzer);
    pthread_join(fuzzer->thread, NULL);

    clean(fuzzer);
    return 0;
}

int client(Fuzzer *fuzzer) {
    uint8_t tab_bits[256];
    uint16_t tab_regs[128];
    modbus_t *ctx = NULL;
    int rc = 0;

    ctx = modbus_new_tcp("127.0.0.1", fuzzer->port);
    if (ctx == NULL) {
        return -1;
    }

    /* Set reasonable timeout for fuzzing */
    modbus_set_response_timeout(ctx, 1, 0);

    if (modbus_connect(ctx) == -1) {
        modbus_free(ctx);
        return -1;
    }

    memset(tab_bits, 0, sizeof(tab_bits));
    memset(tab_regs, 0, sizeof(tab_regs));

    /* Initialize some data for write operations */
    for (int i = 0; i < 128; i++) {
        tab_regs[i] = (uint16_t)(i * 0x100 + i);
    }
    for (int i = 0; i < 256; i++) {
        tab_bits[i] = (i % 2) ? 1 : 0;
    }

    /* Select operation based on first byte of fuzz input */
    uint8_t op = fuzzer->buffer[0] % 12;
    int addr = UT_BITS_ADDRESS;

    switch (op) {
        case 0:
            /* modbus_write_bit (FC 0x05) - Write single coil */
            rc = modbus_write_bit(ctx, addr, 1);
            break;

        case 1:
            /* modbus_write_register (FC 0x06) - Write single register */
            rc = modbus_write_register(ctx, UT_REGISTERS_ADDRESS, 0x1234);
            break;

        case 2:
            /* modbus_write_bits (FC 0x0F) - Write multiple coils */
            rc = modbus_write_bits(ctx, addr, 10, tab_bits);
            break;

        case 3:
            /* modbus_write_registers (FC 0x10) - Write multiple registers */
            rc = modbus_write_registers(ctx, UT_REGISTERS_ADDRESS, 10, tab_regs);
            break;

        case 4:
            /* modbus_mask_write_register (FC 0x16) */
            rc = modbus_mask_write_register(ctx, UT_REGISTERS_ADDRESS, 0xFF00, 0x00FF);
            break;

        case 5:
            /* modbus_write_and_read_registers (FC 0x17) - then use float conversion */
            rc = modbus_write_and_read_registers(ctx, UT_REGISTERS_ADDRESS, 5, tab_regs,
                                                  UT_REGISTERS_ADDRESS, 5, tab_regs);
            if (rc >= 2) {
                /* Test float conversion with fuzzer-controlled register values */
                volatile float f = modbus_get_float_abcd(tab_regs);
                (void)f;
            }
            break;

        case 6:
            /* modbus_read_input_bits (FC 0x02) */
            rc = modbus_read_input_bits(ctx, UT_INPUT_BITS_ADDRESS, 10, tab_bits);
            break;

        case 7:
            /* modbus_read_input_registers (FC 0x04) - then use float conversion */
            rc = modbus_read_input_registers(ctx, UT_INPUT_REGISTERS_ADDRESS, 10, tab_regs);
            if (rc >= 2) {
                volatile float f = modbus_get_float_dcba(tab_regs);
                (void)f;
            }
            break;

        case 8:
            /* modbus_report_slave_id (FC 0x11) */
            rc = modbus_report_slave_id(ctx, 256, tab_bits);
            break;

        case 9:
            /* modbus_read_registers (FC 0x03) - test all float conversions */
            rc = modbus_read_registers(ctx, UT_REGISTERS_ADDRESS, 10, tab_regs);
            if (rc >= 2) {
                volatile float f1 = modbus_get_float_abcd(tab_regs);
                volatile float f2 = modbus_get_float_dcba(tab_regs);
                volatile float f3 = modbus_get_float_badc(tab_regs);
                volatile float f4 = modbus_get_float_cdab(tab_regs);
                (void)f1; (void)f2; (void)f3; (void)f4;
            }
            break;

        case 10:
            /* modbus_read_bits (FC 0x01) */
            rc = modbus_read_bits(ctx, UT_BITS_ADDRESS, 32, tab_bits);
            break;

        case 11:
            /* Read max registers to test boundary */
            rc = modbus_read_registers(ctx, UT_REGISTERS_ADDRESS,
                                       MODBUS_MAX_READ_REGISTERS, tab_regs);
            if (rc >= 2) {
                for (int i = 0; i < rc - 1; i += 2) {
                    volatile float f = modbus_get_float_abcd(&tab_regs[i]);
                    (void)f;
                }
            }
            break;
    }

    modbus_close(ctx);
    modbus_free(ctx);

    return rc;
}
