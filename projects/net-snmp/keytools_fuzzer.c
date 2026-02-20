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
 * Fuzzer targeting key generation and key-change functions in keytools.c.
 * These functions process passwords and key material for SNMPv3 USM.
 * Bugs here can lead to buffer overflows or incorrect key derivation.
 *
 * Targets: generate_Ku, generate_kul, encode_keychange, decode_keychange
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/keytools.h>
#include <net-snmp/library/scapi.h>
#include <net-snmp/library/transform_oids.h>
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
    sc_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3)
        return 0;

    af_gb_init();

    const uint8_t *d = data;
    size_t s = size;

    uint8_t op_selector = d[0];
    uint8_t oid_selector = d[1];
    d += 2;
    s -= 2;

    const oid *hash_oid;
    u_int hash_oid_len;

    if (oid_selector % 2 == 0) {
        hash_oid = usmHMACSHA1AuthProtocol;
        hash_oid_len = sizeof(usmHMACSHA1AuthProtocol) / sizeof(oid);
    } else {
#ifndef NETSNMP_DISABLE_MD5
        hash_oid = usmHMACMD5AuthProtocol;
        hash_oid_len = sizeof(usmHMACMD5AuthProtocol) / sizeof(oid);
#else
        hash_oid = usmHMACSHA1AuthProtocol;
        hash_oid_len = sizeof(usmHMACSHA1AuthProtocol) / sizeof(oid);
#endif
    }

    switch (op_selector % 4) {
    case 0: {
        /*
         * generate_Ku: derive a master key from a passphrase.
         * The passphrase is fuzz-controlled.
         */
        u_char Ku[USM_LENGTH_KU_HASHBLOCK];
        size_t ku_len = sizeof(Ku);
        generate_Ku(hash_oid, hash_oid_len, d, s, Ku, &ku_len);
        break;
    }
    case 1: {
        /*
         * generate_kul: localize a key with an engine ID.
         * Both the master key and engine ID come from fuzz data.
         */
        u_char *engine_id = af_gb_get_random_data(&d, &s, 16);
        if (!engine_id)
            break;
        u_char *ku = af_gb_get_random_data(&d, &s, 20);
        if (!ku)
            break;
        u_char kul[USM_LENGTH_KU_HASHBLOCK];
        size_t kul_len = sizeof(kul);
        generate_kul(hash_oid, hash_oid_len,
                     engine_id, 16,
                     ku, 20,
                     kul, &kul_len);
        break;
    }
    case 2: {
        /*
         * encode_keychange: encode a key change value given old and new keys.
         * Both keys are fuzz-controlled.
         */
        u_char *oldkey = af_gb_get_random_data(&d, &s, 20);
        if (!oldkey)
            break;
        u_char *newkey = af_gb_get_random_data(&d, &s, 20);
        if (!newkey)
            break;
        u_char kcstring[128];
        size_t kcstring_len = sizeof(kcstring);
        encode_keychange(hash_oid, hash_oid_len,
                         oldkey, 20,
                         newkey, 20,
                         kcstring, &kcstring_len);
        break;
    }
    case 3: {
        /*
         * decode_keychange: decode a key change string to derive new key.
         * The old key and keychange string are fuzz-controlled.
         */
        u_char *oldkey = af_gb_get_random_data(&d, &s, 20);
        if (!oldkey)
            break;
        /* keychange string length must be even as per RFC */
        size_t kc_len = s;
        if (kc_len < 2)
            break;
        /* Make kc_len even */
        kc_len &= ~(size_t)1;
        u_char *kcstring = af_gb_get_random_data(&d, &s, kc_len);
        if (!kcstring)
            break;
        u_char newkey[USM_LENGTH_KU_HASHBLOCK];
        size_t newkey_len = sizeof(newkey);
        decode_keychange(hash_oid, hash_oid_len,
                         oldkey, 20,
                         kcstring, kc_len,
                         newkey, &newkey_len);
        break;
    }
    }

    af_gb_cleanup();
    return 0;
}
