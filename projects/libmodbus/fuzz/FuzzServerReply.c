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
 * FuzzServerReply - Tests server response generation
 * Extends FuzzServer.c to call modbus_reply() and modbus_reply_exception()
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <modbus.h>
#include "unit-test.h"

#define PORT 8080
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

int server(Fuzzer *fuzzer);

void *client(void *args) {
    Fuzzer *fuzzer = (Fuzzer *)args;
    int sockfd;
    struct sockaddr_in serv_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(fuzzer->port);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    while (1) {
        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            continue;
        } else {
            break;
        }
    }

    send(sockfd, fuzzer->buffer, fuzzer->size, 0);

    /* Receive the response to complete the transaction */
    char response[MODBUS_TCP_MAX_ADU_LENGTH];
    recv(sockfd, response, sizeof(response), 0);

    close(sockfd);
    pthread_exit(NULL);
}

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < kMinInputLength || size > kMaxInputLength) {
        return 0;
    }

    Fuzzer *fuzzer = (Fuzzer *)malloc(sizeof(Fuzzer));
    if (!fuzzer) return 0;

    fuzzer->port = PORT;
    fuzzer->size = size;
    fuzzer->buffer = data;

    pthread_create(&fuzzer->thread, NULL, client, fuzzer);
    server(fuzzer);
    pthread_join(fuzzer->thread, NULL);

    free(fuzzer);
    return 0;
}

int server(Fuzzer *fuzzer) {
    int s = -1;
    modbus_t *ctx;
    modbus_mapping_t *mb_mapping;
    int rc;
    int i;
    uint8_t *query;

    ctx = modbus_new_tcp("127.0.0.1", fuzzer->port);
    if (ctx == NULL) {
        return -1;
    }

    query = malloc(MODBUS_TCP_MAX_ADU_LENGTH);
    if (query == NULL) {
        modbus_free(ctx);
        return -1;
    }

    mb_mapping = modbus_mapping_new_start_address(
        UT_BITS_ADDRESS, UT_BITS_NB,
        UT_INPUT_BITS_ADDRESS, UT_INPUT_BITS_NB,
        UT_REGISTERS_ADDRESS, UT_REGISTERS_NB_MAX,
        UT_INPUT_REGISTERS_ADDRESS, UT_INPUT_REGISTERS_NB);

    if (mb_mapping == NULL) {
        free(query);
        modbus_free(ctx);
        return -1;
    }

    /* Initialize input values */
    modbus_set_bits_from_bytes(mb_mapping->tab_input_bits, 0, UT_INPUT_BITS_NB,
                               UT_INPUT_BITS_TAB);

    for (i = 0; i < UT_INPUT_REGISTERS_NB; i++) {
        mb_mapping->tab_input_registers[i] = UT_INPUT_REGISTERS_TAB[i];
    }

    /* Initialize some coils and registers with data */
    for (i = 0; i < UT_BITS_NB && i < mb_mapping->nb_bits; i++) {
        mb_mapping->tab_bits[i] = (i % 2) ? 1 : 0;
    }
    for (i = 0; i < UT_REGISTERS_NB_MAX && i < mb_mapping->nb_registers; i++) {
        mb_mapping->tab_registers[i] = (uint16_t)(i * 0x100 + i);
    }

    s = modbus_tcp_listen(ctx, 1);
    if (s == -1) {
        modbus_mapping_free(mb_mapping);
        free(query);
        modbus_free(ctx);
        return -1;
    }

    modbus_tcp_accept(ctx, &s);

    rc = modbus_receive(ctx, query);
    if (rc > 0) {
        /* Generate response - this exercises reply code paths */
        modbus_reply(ctx, query, rc, mb_mapping);

        /* Also test exception replies based on fuzz input */
        if (fuzzer->size > 0 && (fuzzer->buffer[0] & 1)) {
            uint8_t exception_code = (fuzzer->buffer[0] % 12) + 1;
            modbus_reply_exception(ctx, query, exception_code);
        }
    }

    if (s != -1) {
        close(s);
    }

    modbus_mapping_free(mb_mapping);
    free(query);
    modbus_close(ctx);
    modbus_free(ctx);

    return rc;
}
