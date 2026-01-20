
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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
};
typedef struct Fuzzer Fuzzer;

int client(Fuzzer *fuzzer);

int fuzzinit(Fuzzer *fuzzer){
    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(server_addr);

    fuzzer->socket = socket(AF_INET, SOCK_STREAM, 0);
    if (fuzzer->socket < 0) {
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(0);  // Let OS assign port
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    setsockopt(fuzzer->socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    if (bind(fuzzer->socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(fuzzer->socket);
        return -1;
    }

    // Get the assigned port
    if (getsockname(fuzzer->socket, (struct sockaddr*)&server_addr, &addr_len) < 0) {
        close(fuzzer->socket);
        return -1;
    }
    fuzzer->port = ntohs(server_addr.sin_port);

    if (listen(fuzzer->socket, 1) < 0) {
        close(fuzzer->socket);
        return -1;
    }

    return 0;
}

void *Server(void *args){

    Fuzzer *fuzzer = (Fuzzer*)args;
    {
        int client;
        char clientData[10240];
        struct sockaddr_in clientAddr;
        uint32_t clientSZ = sizeof(clientAddr);

        client = accept(fuzzer->socket, (struct sockaddr*)&clientAddr, &clientSZ);
        if (client < 0) {
            pthread_exit(NULL);
        }

        // Set socket timeouts to avoid blocking indefinitely
        struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};  // 100ms
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        send(client, fuzzer->buffer, fuzzer->size, 0);
        recv(client, clientData, sizeof(clientData), 0);

        send(client, fuzzer->buffer, fuzzer->size, 0);
        recv(client, clientData, sizeof(clientData), 0);

        shutdown(client,SHUT_RDWR);
        close(client);
    }
    pthread_exit(NULL);
}

void clean(Fuzzer *fuzzer){
    {//Server
        shutdown(fuzzer->socket,SHUT_RDWR);
        close(fuzzer->socket);
    }
    free(fuzzer);
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

    fuzzer->port = 0;  // Will be set by fuzzinit
    fuzzer->size = size;
    fuzzer->buffer = (uint8_t*)data;

    if (fuzzinit(fuzzer) < 0) {
        free(fuzzer);
        return 0;
    }

    if (pthread_create(&fuzzer->thread, NULL, Server, fuzzer) != 0) {
        close(fuzzer->socket);
        free(fuzzer);
        return 0;
    }
    client(fuzzer);
    pthread_join(fuzzer->thread, NULL);  /* To Avoid UAF */

    clean(fuzzer);
    return 0;
}

int client(Fuzzer *fuzzer){

    uint8_t *tab_rp_bits = NULL;
    uint16_t *tab_rp_registers = NULL;
    modbus_t *ctx = NULL;
    int nb_points;
    int rc;

    ctx = modbus_new_tcp("127.0.0.1", fuzzer->port);

    if (ctx == NULL) {
        fprintf(stderr, "Unable to allocate libmodbus context\n");
        return -1;
    }

    // Set short timeouts for fuzzing (50ms response, 10ms byte)
    modbus_set_response_timeout(ctx, 0, 50000);
    modbus_set_byte_timeout(ctx, 0, 10000);

    if (modbus_connect(ctx) == -1) {
        fprintf(stderr, "Connection failed: %s\n", modbus_strerror(errno));
        modbus_free(ctx);
        return -1;
    }

    /* Allocate and initialize the memory to store the bits */
    nb_points = (UT_BITS_NB > UT_INPUT_BITS_NB) ? UT_BITS_NB : UT_INPUT_BITS_NB;
    tab_rp_bits = (uint8_t *) malloc(nb_points * sizeof(uint8_t));
    memset(tab_rp_bits, 0, nb_points * sizeof(uint8_t));

    /* Allocate and initialize the memory to store the registers */
    nb_points = (UT_REGISTERS_NB > UT_INPUT_REGISTERS_NB) ?
        UT_REGISTERS_NB : UT_INPUT_REGISTERS_NB;
    tab_rp_registers = (uint16_t *) malloc(nb_points * sizeof(uint16_t));
    memset(tab_rp_registers, 0, nb_points * sizeof(uint16_t));

//Read
    rc = modbus_read_bits(ctx, UT_BITS_ADDRESS, UT_BITS_NB, tab_rp_bits);

    rc = modbus_read_registers(ctx, UT_REGISTERS_ADDRESS,
                               UT_REGISTERS_NB, tab_rp_registers);

    /* Free the memory */
    free(tab_rp_bits);
    free(tab_rp_registers);

    /* Close the connection */
    modbus_close(ctx);
    modbus_free(ctx);

    return rc;
}
