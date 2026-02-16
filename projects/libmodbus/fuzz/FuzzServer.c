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

/* FuzzServer.c - Tests server-side request processing
 * Exercises modbus_receive() and modbus_reply() for all function codes.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <modbus.h>
#include "unit-test.h"

#define kMinInputLength 9
#define kMaxInputLength MODBUS_RTU_MAX_ADU_LENGTH

// Persistent state
static int g_listen_fd = -1;
static uint16_t g_port = 0;
static modbus_mapping_t *g_mb_mapping = NULL;
static uint8_t *g_query = NULL;

// Client thread state - using atomics for lock-free sync
static pthread_t g_client_thread;
static atomic_int g_state = 0;  // 0=idle, 1=work_ready, 2=work_done
static atomic_int g_shutdown = 0;
static const uint8_t *g_data = NULL;
static size_t g_size = 0;

void *client_thread(void *args) {
    (void)args;
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(g_port);  // Fixed port, known at init

    while (!atomic_load(&g_shutdown)) {
        // Spin-wait for work
        while (atomic_load(&g_state) != 1) {
            if (atomic_load(&g_shutdown)) return NULL;
            sched_yield();
        }

        const uint8_t *data = g_data;
        size_t size = g_size;

        // Connect and send
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd >= 0) {
            struct timeval tv = {.tv_sec = 0, .tv_usec = 50000};  // 50ms
            setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

            if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
                send(sockfd, data, size, 0);
            }
            close(sockfd);
        }

        // Signal done
        atomic_store(&g_state, 2);
    }

    return NULL;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;

    signal(SIGPIPE, SIG_IGN);

    // Create persistent listening socket
    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) {
        return -1;
    }

    int optval = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(0);  // Ephemeral port

    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
        return -1;
    }

    // Get assigned port
    socklen_t addr_len = sizeof(addr);
    if (getsockname(g_listen_fd, (struct sockaddr *)&addr, &addr_len) == 0) {
        g_port = ntohs(addr.sin_port);
    }

    if (listen(g_listen_fd, 5) < 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
        return -1;
    }

    // Set accept timeout
    struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};  // 100ms
    setsockopt(g_listen_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Pre-allocate query buffer
    g_query = malloc(MODBUS_TCP_MAX_ADU_LENGTH);

    // Pre-allocate and initialize mapping
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

    // Start persistent client thread
    pthread_create(&g_client_thread, NULL, client_thread, NULL);

    return 0;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < kMinInputLength || size > kMaxInputLength) {
        return 0;
    }

    if (g_listen_fd < 0 || g_query == NULL || g_mb_mapping == NULL) {
        return 0;
    }

    // Signal client to connect
    g_data = data;
    g_size = size;
    atomic_store(&g_state, 1);  // work_ready

    // Accept connection
    int client_fd = accept(g_listen_fd, NULL, NULL);
    if (client_fd < 0) {
        // Wait for client to finish
        while (atomic_load(&g_state) != 2) {
            sched_yield();
        }
        atomic_store(&g_state, 0);
        return 0;
    }

    // Create modbus context and set the accepted socket
    modbus_t *ctx = modbus_new_tcp(NULL, 0);
    if (ctx == NULL) {
        close(client_fd);
        while (atomic_load(&g_state) != 2) {
            sched_yield();
        }
        atomic_store(&g_state, 0);
        return 0;
    }

    modbus_set_socket(ctx, client_fd);
    modbus_set_response_timeout(ctx, 0, 10000);
    modbus_set_byte_timeout(ctx, 0, 5000);

    // Receive and process
    int rc = modbus_receive(ctx, g_query);
    if (rc > 0) {
        modbus_reply(ctx, g_query, rc, g_mb_mapping);
    }

    // Cleanup
    close(client_fd);
    modbus_free(ctx);

    // Wait for client to finish
    while (atomic_load(&g_state) != 2) {
        sched_yield();
    }
    atomic_store(&g_state, 0);  // back to idle

    return 0;
}
