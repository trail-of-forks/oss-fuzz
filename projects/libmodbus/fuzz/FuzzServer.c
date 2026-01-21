/* Copyright 2021 Google LLC
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
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <modbus.h>
#include "unit-test.h"

#define kMinInputLength 9
#define kMaxInputLength MODBUS_RTU_MAX_ADU_LENGTH

struct Fuzzer{
    uint16_t    port;
    char*       file;

    FILE*       inFile;
    uint64_t    size;
    uint8_t*    buffer;

    pthread_t   thread;
    int         socket;

    // Synchronization for dynamic port
    pthread_mutex_t ready_mutex;
    pthread_cond_t  ready_cond;
    int             server_ready;
};
typedef struct Fuzzer Fuzzer;

int server(Fuzzer *fuzzer);

void *client(void *args){

    Fuzzer *fuzzer = (Fuzzer*)args;
    int sockfd;
    struct sockaddr_in serv_addr;

    // Wait for server to be ready with port assigned
    pthread_mutex_lock(&fuzzer->ready_mutex);
    while (fuzzer->server_ready == 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 50000000;  // 50ms timeout
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }
        int rc = pthread_cond_timedwait(&fuzzer->ready_cond, &fuzzer->ready_mutex, &ts);
        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&fuzzer->ready_mutex);
            pthread_exit(NULL);
        }
    }
    // Check if server failed
    if (fuzzer->server_ready < 0) {
        pthread_mutex_unlock(&fuzzer->ready_mutex);
        pthread_exit(NULL);
    }
    uint16_t port = fuzzer->port;
    pthread_mutex_unlock(&fuzzer->ready_mutex);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        pthread_exit(NULL);
    }

    // Set send timeout
    struct timeval tv = {.tv_sec = 0, .tv_usec = 20000};  // 20ms
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Quick retry loop without sleeping - server should be ready
    int connected = 0;
    for (int attempt = 0; attempt < 10 && !connected; attempt++) {
        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
            connected = 1;
        }
    }
    if (!connected) {
        close(sockfd);
        pthread_exit(NULL);
    }

    send(sockfd, fuzzer->buffer, fuzzer->size, 0);

    close(sockfd);
    pthread_exit(NULL);
}

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int initialized = 0;
    if (!initialized) {
        signal(SIGPIPE, SIG_IGN);
        initialized = 1;
    }

    if (size < kMinInputLength || size > kMaxInputLength){
        return 0;
    }

    Fuzzer *fuzzer = (Fuzzer*)malloc(sizeof(Fuzzer));
    if (fuzzer == NULL) {
        return 0;
    }

    fuzzer->port = 0;  // Will be set by server with dynamic port
    fuzzer->size = size;
    fuzzer->buffer = (uint8_t*)data;
    fuzzer->server_ready = 0;

    pthread_mutex_init(&fuzzer->ready_mutex, NULL);
    pthread_cond_init(&fuzzer->ready_cond, NULL);

    if (pthread_create(&fuzzer->thread, NULL, client, fuzzer) != 0) {
        pthread_mutex_destroy(&fuzzer->ready_mutex);
        pthread_cond_destroy(&fuzzer->ready_cond);
        free(fuzzer);
        return 0;
    }
    server(fuzzer);
    pthread_join(fuzzer->thread, NULL);  /* Avoid UAF */

    pthread_mutex_destroy(&fuzzer->ready_mutex);
    pthread_cond_destroy(&fuzzer->ready_cond);
    free(fuzzer);
    return 0;
}

int server(Fuzzer *fuzzer)
{
    int s = -1;
    modbus_t *ctx;
    modbus_mapping_t *mb_mapping;
    int rc;
    int i;
    uint8_t *query;

    // Use port 0 for dynamic port allocation
    ctx = modbus_new_tcp("127.0.0.1", 0);
    if (ctx == NULL) {
        // Signal failure to client
        pthread_mutex_lock(&fuzzer->ready_mutex);
        fuzzer->server_ready = -1;
        pthread_cond_signal(&fuzzer->ready_cond);
        pthread_mutex_unlock(&fuzzer->ready_mutex);
        return -1;
    }

    // Set very short timeouts for fuzzing (10ms response, 5ms byte)
    modbus_set_response_timeout(ctx, 0, 10000);
    modbus_set_byte_timeout(ctx, 0, 5000);

    query = malloc(MODBUS_TCP_MAX_ADU_LENGTH);
    if (query == NULL) {
        modbus_free(ctx);
        pthread_mutex_lock(&fuzzer->ready_mutex);
        fuzzer->server_ready = -1;
        pthread_cond_signal(&fuzzer->ready_cond);
        pthread_mutex_unlock(&fuzzer->ready_mutex);
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
        pthread_mutex_lock(&fuzzer->ready_mutex);
        fuzzer->server_ready = -1;
        pthread_cond_signal(&fuzzer->ready_cond);
        pthread_mutex_unlock(&fuzzer->ready_mutex);
        return -1;
    }

    /* Initialize input values that's can be only done server side. */
    modbus_set_bits_from_bytes(mb_mapping->tab_input_bits, 0, UT_INPUT_BITS_NB,
                               UT_INPUT_BITS_TAB);

    /* Initialize values of INPUT REGISTERS */
    for (i=0; i < UT_INPUT_REGISTERS_NB; i++) {
        mb_mapping->tab_input_registers[i] = UT_INPUT_REGISTERS_TAB[i];
    }

    s = modbus_tcp_listen(ctx, 1);
    if (s < 0) {
        modbus_mapping_free(mb_mapping);
        free(query);
        modbus_free(ctx);
        pthread_mutex_lock(&fuzzer->ready_mutex);
        fuzzer->server_ready = -1;
        pthread_cond_signal(&fuzzer->ready_cond);
        pthread_mutex_unlock(&fuzzer->ready_mutex);
        return -1;
    }

    // Get the dynamically assigned port
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getsockname(s, (struct sockaddr*)&addr, &addr_len) == 0) {
        fuzzer->port = ntohs(addr.sin_port);
    }

    // Set longer timeout on listening socket for accept()
    struct timeval accept_tv = {.tv_sec = 0, .tv_usec = 200000};  // 200ms
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &accept_tv, sizeof(accept_tv));

    // Signal that server is ready with port assigned
    pthread_mutex_lock(&fuzzer->ready_mutex);
    fuzzer->server_ready = 1;
    pthread_cond_signal(&fuzzer->ready_cond);
    pthread_mutex_unlock(&fuzzer->ready_mutex);

    modbus_tcp_accept(ctx, &s);

    rc = modbus_receive(ctx, query);
    if (rc > 0) {
        // Process the request and generate response
        // This exercises the entire modbus_reply() parsing logic for all function codes
        modbus_reply(ctx, query, rc, mb_mapping);
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
