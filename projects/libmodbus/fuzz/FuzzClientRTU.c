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

/* FuzzClientRTU.c - Tests RTU client response parsing with CRC-aware mutator
 * This fuzzer tests the RTU client-side code paths including
 * _modbus_rtu_recv(), _modbus_rtu_check_integrity() (client path),
 * and RTU response length calculation.
 *
 * Uses pipe injection to feed fuzz data as an RTU response frame,
 * exercising modbus_receive_confirmation() code paths.
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
#include "modbus_crc16.h"

#define RTU_MIN_ADU 4   /* slave + function + crc(2) */
#define RTU_MAX_ADU 256
#define RTU_CRC_LEN 2

/* Persistent state */
static uint8_t *g_response = NULL;

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

    /* Pre-allocate response buffer */
    g_response = malloc(MODBUS_RTU_MAX_ADU_LENGTH);
    if (g_response == NULL) {
        return -1;
    }

    return 0;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < RTU_MIN_ADU || size > RTU_MAX_ADU) {
        return 0;
    }

    if (g_response == NULL) {
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

    /* Minimal timeouts - data is already in pipe, just need select() to see it */
    modbus_set_response_timeout(ctx, 0, 100);    /* 100us */
    modbus_set_byte_timeout(ctx, 0, 100);        /* 100us */

    /* Set slave ID from fuzz input for filtering coverage */
    modbus_set_slave(ctx, data[0]);

    /* Write fuzz data (RTU response frame) to pipe */
    ssize_t written = write(pipefd[1], data, size);
    (void)written;
    close(pipefd[1]);  /* Close write end - signals EOF */

    /* Process through libmodbus RTU client path
     * This exercises:
     * - _modbus_rtu_select()
     * - _modbus_rtu_recv()
     * - _modbus_rtu_check_integrity() (client path)
     * - RTU response length calculation
     * - Slave ID filtering
     * - Function code parsing
     *
     * modbus_receive_confirmation() parses the response as a client would,
     * unlike modbus_receive() which processes a request on the server side.
     */
    modbus_receive_confirmation(ctx, g_response);

    /* Cleanup */
    close(pipefd[0]);
    modbus_free(ctx);

    return 0;
}
