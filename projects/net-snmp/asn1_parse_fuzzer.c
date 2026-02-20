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
 * Fuzzer targeting ASN.1/BER primitive codec functions in snmplib/asn1.c.
 * These are the bedrock parsing functions for all SNMP wire-format data.
 * Uses the first byte of fuzz input to select which parser to exercise.
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

    /* Use first byte as selector, rest as parse input */
    uint8_t selector = data[0];
    u_char *input = (u_char *)(data + 1);
    size_t input_len = size - 1;

    /* Make a mutable copy since parsers may modify the length */
    u_char *buf = malloc(input_len);
    if (!buf)
        return 0;
    memcpy(buf, input, input_len);

    size_t remaining = input_len;
    u_char type = 0;

    switch (selector % 11) {
    case 0: {
        /* asn_parse_int */
        long value = 0;
        asn_parse_int(buf, &remaining, &type, &value, sizeof(value));
        break;
    }
    case 1: {
        /* asn_parse_unsigned_int */
        u_long value = 0;
        asn_parse_unsigned_int(buf, &remaining, &type, &value, sizeof(value));
        break;
    }
    case 2: {
        /* asn_parse_string */
        u_char str[512];
        size_t str_len = sizeof(str);
        asn_parse_string(buf, &remaining, &type, str, &str_len);
        break;
    }
    case 3: {
        /* asn_parse_header */
        asn_parse_header(buf, &remaining, &type);
        break;
    }
    case 4: {
        /* asn_parse_objid */
        oid objid[MAX_OID_LEN];
        size_t objid_len = MAX_OID_LEN;
        asn_parse_objid(buf, &remaining, &type, objid, &objid_len);
        break;
    }
    case 5: {
        /* asn_parse_null */
        asn_parse_null(buf, &remaining, &type);
        break;
    }
    case 6: {
        /* asn_parse_bitstring */
        u_char str[512];
        size_t str_len = sizeof(str);
        asn_parse_bitstring(buf, &remaining, &type, str, &str_len);
        break;
    }
    case 7: {
        /* asn_parse_unsigned_int64 */
        struct counter64 c64;
        memset(&c64, 0, sizeof(c64));
        asn_parse_unsigned_int64(buf, &remaining, &type, &c64, sizeof(c64));
        break;
    }
    case 8: {
        /* asn_parse_signed_int64 */
        struct counter64 c64;
        memset(&c64, 0, sizeof(c64));
        asn_parse_signed_int64(buf, &remaining, &type, &c64, sizeof(c64));
        break;
    }
    case 9: {
        /* asn_parse_float */
        float fval = 0;
        asn_parse_float(buf, &remaining, &type, &fval, sizeof(fval));
        break;
    }
    case 10: {
        /* asn_parse_double */
        double dval = 0;
        asn_parse_double(buf, &remaining, &type, &dval, sizeof(dval));
        break;
    }
    }

    free(buf);
    return 0;
}
