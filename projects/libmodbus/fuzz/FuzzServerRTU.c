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

/* FuzzServerRTU.c - Tests RTU backend with CRC-aware custom mutator
 * This fuzzer tests the RTU framing and CRC validation code paths
 * by using a custom mutator that ensures valid CRC-16 checksums.
 *
 * Uses pipe injection to feed fuzz data through the RTU backend,
 * exercising modbus_receive() and modbus_reply() code paths.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <signal.h>
#include <fcntl.h>

#include <modbus.h>
#include "unit-test.h"
#include "modbus_crc16.h"

#define RTU_MIN_ADU 4   /* slave + function + crc(2) */
#define RTU_MAX_ADU 256
#define RTU_CRC_LEN 2

/* Persistent state */
static modbus_mapping_t *g_mb_mapping = NULL;
static uint8_t *g_query = NULL;

/* External libFuzzer mutation function */
extern size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

/*
 * Custom mutator: ensures valid CRC-16 after mutation.
 * 1. Strip CRC from input
 * 2. Apply default mutation to payload
 * 3. Recompute and append valid CRC
 */
size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                size_t MaxSize, unsigned int Seed) {
    (void)Seed;

    if (Size < RTU_MIN_ADU) {
        if (MaxSize < RTU_MIN_ADU) return 0;
        Data[0] = 0x01;  /* Slave ID */
        Data[1] = 0x03;  /* FC: Read Registers */
        modbus_crc16_append(Data, 2);
        return RTU_MIN_ADU;
    }

    size_t payload_len = Size - RTU_CRC_LEN;
    size_t max_payload = MaxSize - RTU_CRC_LEN;
    if (max_payload < 2) return 0;

    /* Mutate payload (without CRC) */
    size_t new_len = LLVMFuzzerMutate(Data, payload_len, max_payload);
    if (new_len < 2) new_len = 2;

    /* Append valid CRC */
    modbus_crc16_append(Data, new_len);
    return new_len + RTU_CRC_LEN;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;

    signal(SIGPIPE, SIG_IGN);

    /* Pre-allocate query buffer */
    g_query = malloc(MODBUS_RTU_MAX_ADU_LENGTH);
    if (g_query == NULL) {
        return -1;
    }

    /* Pre-allocate and initialize mapping */
    g_mb_mapping = modbus_mapping_new_start_address(
        UT_BITS_ADDRESS, UT_BITS_NB,
        UT_INPUT_BITS_ADDRESS, UT_INPUT_BITS_NB,
        UT_REGISTERS_ADDRESS, UT_REGISTERS_NB_MAX,
        UT_INPUT_REGISTERS_ADDRESS, UT_INPUT_REGISTERS_NB);

    if (g_mb_mapping != NULL) {
        modbus_set_bits_from_bytes(g_mb_mapping->tab_input_bits, 0, UT_INPUT_BITS_NB,
                                   UT_INPUT_BITS_TAB);
        for (int i = 0; i < UT_INPUT_REGISTERS_NB; i++) {
            g_mb_mapping->tab_input_registers[i] = UT_INPUT_REGISTERS_TAB[i];
        }
    }

    return 0;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < RTU_MIN_ADU || size > RTU_MAX_ADU) {
        return 0;
    }

    if (g_query == NULL || g_mb_mapping == NULL) {
        return 0;
    }

    /* Create pipe for data injection */
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        return 0;
    }

    /* Set read end to non-blocking to avoid hangs */
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    /* Create RTU context */
    modbus_t *ctx = modbus_new_rtu("/dev/null", 9600, 'N', 8, 1);
    if (ctx == NULL) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 0;
    }

    /* Inject pipe read end as the "serial port" */
    modbus_set_socket(ctx, pipefd[0]);

    /* Very short timeouts to avoid blocking */
    modbus_set_response_timeout(ctx, 0, 5000);   /* 5ms */
    modbus_set_byte_timeout(ctx, 0, 1000);       /* 1ms */

    /* Set slave ID from fuzz input for filtering coverage */
    uint8_t slave_id = data[0];
    modbus_set_slave(ctx, slave_id);

    /* Write fuzz data to pipe */
    ssize_t written = write(pipefd[1], data, size);
    (void)written;
    close(pipefd[1]);  /* Close write end - signals EOF */

    /* Process through libmodbus RTU backend
     * This exercises:
     * - _modbus_rtu_select()
     * - _modbus_rtu_recv()
     * - _modbus_rtu_check_integrity() - CRC validation
     * - Slave ID filtering
     * - Function code parsing
     */
    int rc = modbus_receive(ctx, g_query);

    if (rc > 0) {
        /* Valid request - exercise reply generation
         * This exercises:
         * - All FC handlers in modbus_reply()
         * - _modbus_rtu_build_response_basis()
         * - _modbus_rtu_send_msg_pre() - CRC computation
         * - _modbus_rtu_send() - will fail on closed pipe, that's OK
         */
        modbus_reply(ctx, g_query, rc, g_mb_mapping);
    }

    /* Cleanup */
    close(pipefd[0]);
    modbus_free(ctx);

    return 0;
}
