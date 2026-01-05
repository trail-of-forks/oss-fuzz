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
 * FuzzRawRequest - Tests raw request/response handling
 * Uses socketpair for lightweight communication without TCP overhead
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <modbus.h>

#define kMinInputLength 5
#define kMaxInputLength MODBUS_TCP_MAX_ADU_LENGTH

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < kMinInputLength || size > kMaxInputLength) {
        return 0;
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        return 0;
    }

    modbus_t *ctx = modbus_new_tcp("127.0.0.1", 1502);
    if (ctx == NULL) {
        close(sv[0]);
        close(sv[1]);
        return 0;
    }

    /* Set the socket directly to bypass connection */
    modbus_set_socket(ctx, sv[0]);

    /* Fork to simulate server response */
    pid_t pid = fork();
    if (pid < 0) {
        close(sv[0]);
        close(sv[1]);
        modbus_free(ctx);
        return 0;
    }

    if (pid == 0) {
        /* Child process - acts as server */
        close(sv[0]);

        /* Small delay to ensure client is ready */
        usleep(1000);

        /* Read the request from client */
        uint8_t req[MODBUS_TCP_MAX_ADU_LENGTH];
        ssize_t n = read(sv[1], req, sizeof(req));
        (void)n;

        /* Send fuzz data as response */
        if (size > 2) {
            write(sv[1], data + 2, size - 2);
        }

        close(sv[1]);
        _exit(0);
    }

    /* Parent process - acts as client */
    close(sv[1]);

    /* Extract flags/transaction ID from first two bytes */
    uint16_t tid = ((uint16_t)data[0] << 8) | data[1];

    /* Build a minimal raw request */
    uint8_t raw_req[MODBUS_TCP_MAX_ADU_LENGTH];
    size_t raw_len = (size > 2) ? size - 2 : 0;
    if (raw_len > MODBUS_TCP_MAX_ADU_LENGTH - 6) {
        raw_len = MODBUS_TCP_MAX_ADU_LENGTH - 6;
    }

    if (raw_len > 0) {
        memcpy(raw_req, data + 2, raw_len);
    }

    /* Choose between regular and _tid variant based on high bit */
    if (data[0] & 0x80) {
        modbus_send_raw_request_tid(ctx, raw_req, (int)raw_len, tid & 0x7FFF);
    } else {
        modbus_send_raw_request(ctx, raw_req, (int)raw_len);
    }

    /* Try to receive confirmation */
    uint8_t rsp[MODBUS_TCP_MAX_ADU_LENGTH];
    modbus_receive_confirmation(ctx, rsp);

    /* Cleanup */
    waitpid(pid, NULL, 0);
    close(sv[0]);
    modbus_free(ctx);

    return 0;
}
