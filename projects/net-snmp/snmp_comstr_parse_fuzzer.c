/*
 * Copyright (c) 2025, Net-snmp authors
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Fuzzer targeting SNMPv1/v2c community string parsing and building.
 * snmp_comstr_parse() extracts the community string and version from
 * BER-encoded SNMPv1/v2c message headers. This is the first function
 * that processes untrusted data from the network for v1/v2c packets.
 *
 * Targets: snmp_comstr_parse, snmp_comstr_build
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    if (getenv("NETSNMP_DEBUGGING") != NULL) {
        snmp_enable_stderrlog();
        snmp_set_do_debugging(1);
        debug_register_tokens("");
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2)
        return 0;

    uint8_t selector = data[0];
    data++;
    size--;

    switch (selector % 2) {
    case 0: {
        /*
         * snmp_comstr_parse: parse community string from wire format.
         * This is the entry point for all SNMPv1/v2c message processing.
         */
        size_t length = size;
        u_char community[COMMUNITY_MAX_LEN + 1];
        size_t community_len = COMMUNITY_MAX_LEN;
        long version = 0;

        snmp_comstr_parse(NETSNMP_REMOVE_CONST(u_char *, data),
                          &length,
                          community, &community_len, &version);
        break;
    }
    case 1: {
        /*
         * snmp_comstr_build: build community string encoding.
         * Feed it fuzz-controlled community and version data,
         * then try to build a message.
         */
        size_t out_len = size + 256;
        u_char *out_buf = malloc(out_len);
        if (!out_buf)
            break;

        /* Extract a community string from fuzz data */
        size_t comm_len = size > COMMUNITY_MAX_LEN ? COMMUNITY_MAX_LEN : size;
        u_char community[COMMUNITY_MAX_LEN + 1];
        memcpy(community, data, comm_len);
        community[comm_len] = '\0';

        long version = SNMP_VERSION_1;
        if (size > 0 && data[0] % 2)
            version = SNMP_VERSION_2c;

        snmp_comstr_build(out_buf, &out_len,
                          community, &comm_len, &version, size);
        free(out_buf);
        break;
    }
    }

    return 0;
}
