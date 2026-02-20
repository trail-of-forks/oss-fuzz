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
 * Fuzzer targeting SNMPv3 engine ID and engine time management.
 * The LCD (Local Configuration Datastore) time functions manage
 * engine boot/time counters used in USM timeliness checks.
 * Bugs here can lead to replay attack vulnerabilities or DoS
 * through corrupted time synchronization state.
 *
 * Targets: set_enginetime, get_enginetime_ex, search_enginetime_list
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/lcd_time.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ada_fuzz_header.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    if (getenv("NETSNMP_DEBUGGING") != NULL) {
        snmp_enable_stderrlog();
        snmp_set_do_debugging(1);
        debug_register_tokens("");
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10)
        return 0;

    af_gb_init();

    const uint8_t *d = data;
    size_t s = size;

    uint8_t selector = d[0];
    d++;
    s--;

    switch (selector % 3) {
    case 0: {
        /*
         * set_enginetime then get_enginetime_ex: set engine time with
         * fuzz-controlled engine ID and time values, then read back.
         */
        short eid_len = af_get_short(&d, &s);
        eid_len = (eid_len % 32) + 1; /* 1-32 bytes */
        u_char *engine_id = af_gb_get_random_data(&d, &s, eid_len);
        if (!engine_id)
            break;
        u_int boots = (u_int)af_get_int(&d, &s);
        u_int etime = (u_int)af_get_int(&d, &s);
        u_int authenticated = af_get_short(&d, &s) % 2;

        set_enginetime(engine_id, eid_len, boots, etime, authenticated);

        /* Now read it back */
        u_int out_boots = 0, out_time = 0, out_last_time = 0;
        get_enginetime_ex(engine_id, eid_len,
                          &out_boots, &out_time, &out_last_time,
                          authenticated);

        /* Also test search */
        search_enginetime_list(engine_id, eid_len);

        /* Set with different values to exercise update path */
        boots = (u_int)af_get_int(&d, &s);
        etime = (u_int)af_get_int(&d, &s);
        set_enginetime(engine_id, eid_len, boots, etime, authenticated);

        /* Clean up the engine time entry */
        free_enginetime(engine_id, eid_len);
        break;
    }
    case 1: {
        /*
         * Multiple engine IDs: stress-test the engine time list with
         * multiple different engine IDs from fuzz data.
         */
        int count = (af_get_short(&d, &s) % 5) + 1;
        u_char *eids[5];
        short eid_lens[5];

        for (int i = 0; i < count; i++) {
            eid_lens[i] = (af_get_short(&d, &s) % 16) + 1;
            eids[i] = af_gb_get_random_data(&d, &s, eid_lens[i]);
            if (!eids[i]) {
                count = i;
                break;
            }
            u_int boots = (u_int)af_get_int(&d, &s);
            u_int etime = (u_int)af_get_int(&d, &s);
            set_enginetime(eids[i], eid_lens[i], boots, etime, 1);
        }

        /* Look up each one */
        for (int i = 0; i < count; i++) {
            u_int b = 0, t = 0, lt = 0;
            get_enginetime_ex(eids[i], eid_lens[i], &b, &t, &lt, 1);
        }

        /* Clean up */
        for (int i = 0; i < count; i++) {
            free_enginetime(eids[i], eid_lens[i]);
        }
        break;
    }
    case 2: {
        /*
         * Search for non-existent engine IDs, then add and search again.
         */
        short eid_len = (af_get_short(&d, &s) % 32) + 1;
        u_char *engine_id = af_gb_get_random_data(&d, &s, eid_len);
        if (!engine_id)
            break;

        /* Search before insertion (should return NULL) */
        search_enginetime_list(engine_id, eid_len);

        /* Get time for non-existent entry */
        u_int b = 0, t = 0, lt = 0;
        get_enginetime_ex(engine_id, eid_len, &b, &t, &lt, 0);

        /* Now set and get */
        set_enginetime(engine_id, eid_len, 42, 12345, 1);
        get_enginetime_ex(engine_id, eid_len, &b, &t, &lt, 1);

        free_enginetime(engine_id, eid_len);
        break;
    }
    }

    af_gb_cleanup();
    return 0;
}
