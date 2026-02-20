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
 * Fuzzer targeting SCAPI (Security Cryptographic API) functions.
 * These handle HMAC authentication, hashing, encryption, and decryption
 * for SNMPv3 USM security. Bugs here can lead to authentication bypass,
 * buffer overflows in crypto operations, or information disclosure.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
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

/*
 * Map a selector byte to one of the known auth protocol OIDs.
 */
static const oid *get_auth_oid(uint8_t sel, size_t *oid_len) {
    switch (sel % 3) {
    case 0:
        *oid_len = sizeof(usmHMACSHA1AuthProtocol) / sizeof(oid);
        return usmHMACSHA1AuthProtocol;
    case 1:
#ifndef NETSNMP_DISABLE_MD5
        *oid_len = sizeof(usmHMACMD5AuthProtocol) / sizeof(oid);
        return usmHMACMD5AuthProtocol;
#else
        *oid_len = sizeof(usmHMACSHA1AuthProtocol) / sizeof(oid);
        return usmHMACSHA1AuthProtocol;
#endif
    default:
        *oid_len = sizeof(usmHMACSHA1AuthProtocol) / sizeof(oid);
        return usmHMACSHA1AuthProtocol;
    }
}

/*
 * Map a selector byte to one of the known privacy protocol OIDs.
 */
static const oid *get_priv_oid(uint8_t sel, size_t *oid_len) {
    switch (sel % 2) {
    case 0:
        *oid_len = sizeof(usmAESPrivProtocol) / sizeof(oid);
        return usmAESPrivProtocol;
    default:
#ifndef NETSNMP_DISABLE_DES
        *oid_len = sizeof(usmDESPrivProtocol) / sizeof(oid);
        return usmDESPrivProtocol;
#else
        *oid_len = sizeof(usmAESPrivProtocol) / sizeof(oid);
        return usmAESPrivProtocol;
#endif
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 6)
        return 0;

    af_gb_init();

    const uint8_t *d = data;
    size_t s = size;

    uint8_t op_selector = d[0];
    uint8_t oid_selector = d[1];
    d += 2;
    s -= 2;

    switch (op_selector % 5) {
    case 0: {
        /* sc_hash: hash a fuzz-controlled buffer */
        size_t auth_oid_len;
        const oid *auth_oid = get_auth_oid(oid_selector, &auth_oid_len);
        u_char mac[USM_MAX_AUTHSIZE];
        size_t mac_len = sizeof(mac);
        sc_hash(auth_oid, auth_oid_len, d, s, mac, &mac_len);
        break;
    }
    case 1: {
        /* sc_generate_keyed_hash: HMAC with fuzz-controlled key and message */
        size_t auth_oid_len;
        const oid *auth_oid = get_auth_oid(oid_selector, &auth_oid_len);
        u_char *key = af_gb_get_random_data(&d, &s, 32);
        if (!key)
            break;
        u_char mac[USM_MAX_AUTHSIZE];
        size_t mac_len = sizeof(mac);
        sc_generate_keyed_hash(auth_oid, auth_oid_len,
                               key, 32,
                               d, (u_int)s,
                               mac, &mac_len);
        break;
    }
    case 2: {
        /* sc_check_keyed_hash: verify HMAC with fuzz-controlled inputs */
        size_t auth_oid_len;
        const oid *auth_oid = get_auth_oid(oid_selector, &auth_oid_len);
        u_char *key = af_gb_get_random_data(&d, &s, 32);
        if (!key)
            break;
        u_char *mac_data = af_gb_get_random_data(&d, &s, 12);
        if (!mac_data)
            break;
        sc_check_keyed_hash(auth_oid, auth_oid_len,
                            key, 32,
                            d, (u_int)s,
                            mac_data, 12);
        break;
    }
    case 3: {
        /* sc_encrypt: encrypt with fuzz-controlled key, IV, and plaintext */
        size_t priv_oid_len;
        const oid *priv_oid = get_priv_oid(oid_selector, &priv_oid_len);
        u_char *key = af_gb_get_random_data(&d, &s, 32);
        if (!key)
            break;
        u_char *iv = af_gb_get_random_data(&d, &s, 16);
        if (!iv)
            break;
        if (s == 0)
            break;
        u_char *ciphertext = af_gb_alloc_data(s + 64);
        if (!ciphertext)
            break;
        size_t ct_len = s + 64;
        sc_encrypt(priv_oid, priv_oid_len,
                   key, 32,
                   iv, 16,
                   d, (u_int)s,
                   ciphertext, &ct_len);
        break;
    }
    case 4: {
        /* sc_decrypt: decrypt with fuzz-controlled key, IV, and ciphertext */
        size_t priv_oid_len;
        const oid *priv_oid = get_priv_oid(oid_selector, &priv_oid_len);
        u_char *key = af_gb_get_random_data(&d, &s, 32);
        if (!key)
            break;
        u_char *iv = af_gb_get_random_data(&d, &s, 16);
        if (!iv)
            break;
        if (s == 0)
            break;
        u_char *ct = af_gb_get_random_data(&d, &s, s);
        if (!ct)
            break;
        size_t ct_used = s; /* amount we consumed */
        /* Recompute: ct was allocated from data before s was decremented */
        u_int ct_len_val = size - (d - data) - 2;
        if (ct_len_val == 0)
            break;
        u_char *plaintext = af_gb_alloc_data(ct_len_val + 64);
        if (!plaintext)
            break;
        size_t pt_len = ct_len_val + 64;
        sc_decrypt(priv_oid, priv_oid_len,
                   key, 32,
                   iv, 16,
                   ct, ct_len_val,
                   plaintext, &pt_len);
        break;
    }
    }

    af_gb_cleanup();
    return 0;
}
