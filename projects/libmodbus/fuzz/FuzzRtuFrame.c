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
 * FuzzRtuFrame - Tests RTU protocol handling including CRC validation
 * Linux-only harness using PTY (pseudo-terminal) for serial simulation
 */

#ifdef __linux__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <pty.h>
#include <termios.h>

#include <modbus.h>

#define kMinInputLength 4
#define kMaxInputLength MODBUS_RTU_MAX_ADU_LENGTH

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < kMinInputLength || size > kMaxInputLength) {
        return 0;
    }

    int master, slave;
    char slave_name[256];

    /* Create pseudo-terminal pair */
    if (openpty(&master, &slave, slave_name, NULL, NULL) < 0) {
        return 0;
    }

    /* Create RTU context using slave PTY */
    modbus_t *ctx = modbus_new_rtu(slave_name, 9600, 'N', 8, 1);
    if (ctx == NULL) {
        close(master);
        close(slave);
        return 0;
    }

    /* Configure RTU using fuzz data */
    if (size >= 2) {
        /* Set serial mode: RS232 (0) or RS485 (1) */
        modbus_rtu_set_serial_mode(ctx, data[0] & 1);

        /* Set RTS mode: NONE (0), UP (1), or DOWN (2) */
        modbus_rtu_set_rts(ctx, (data[0] >> 1) & 3);

        /* Set slave ID (0-247 valid range) */
        modbus_set_slave(ctx, data[1] % 248);
    }

    /* Set RTS delay using fuzz data */
    if (size >= 4) {
        int delay = ((int)data[2] << 8) | data[3];
        modbus_rtu_set_rts_delay(ctx, delay);
    }

    /* Get configuration values to exercise getter paths */
    int serial_mode = modbus_rtu_get_serial_mode(ctx);
    int rts_mode = modbus_rtu_get_rts(ctx);
    int rts_delay = modbus_rtu_get_rts_delay(ctx);
    (void)serial_mode;
    (void)rts_mode;
    (void)rts_delay;

    /* Fork to write data to master (simulating remote device) */
    pid_t pid = fork();
    if (pid < 0) {
        close(master);
        close(slave);
        modbus_free(ctx);
        return 0;
    }

    if (pid == 0) {
        /* Child process - simulates remote RTU device */
        close(slave);

        /* Small delay to let parent connect */
        usleep(10000);

        /* Write fuzz data as RTU frame (skip config bytes) */
        if (size > 4) {
            write(master, data + 4, size - 4);
        }

        close(master);
        _exit(0);
    }

    /* Parent process - RTU client/server */
    close(master);
    close(slave);  /* Close our copy; modbus_connect() opens its own fd via slave_name */

    if (modbus_connect(ctx) == 0) {
        modbus_mapping_t *mb_mapping = modbus_mapping_new(100, 100, 100, 100);

        if (mb_mapping) {
            /* Initialize some mapping data */
            for (int i = 0; i < 100 && i < mb_mapping->nb_bits; i++) {
                mb_mapping->tab_bits[i] = (i % 2) ? 1 : 0;
            }
            for (int i = 0; i < 100 && i < mb_mapping->nb_registers; i++) {
                mb_mapping->tab_registers[i] = (uint16_t)(i * 256 + i);
            }

            /* Set a short timeout since we're fuzzing */
            modbus_set_response_timeout(ctx, 0, 100000);  /* 100ms */

            uint8_t query[MODBUS_RTU_MAX_ADU_LENGTH];
            int rc = modbus_receive(ctx, query);

            if (rc > 0) {
                /* Generate response - exercises RTU reply encoding */
                modbus_reply(ctx, query, rc, mb_mapping);
            }

            modbus_mapping_free(mb_mapping);
        }

        modbus_close(ctx);
    }

    /* Wait for child and cleanup */
    waitpid(pid, NULL, 0);
    modbus_free(ctx);

    return 0;
}

#else /* Non-Linux platforms */

#include <stdint.h>
#include <stddef.h>

/* Empty harness for non-Linux platforms */
extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)data;
    (void)size;
    return 0;
}

#endif /* __linux__ */
