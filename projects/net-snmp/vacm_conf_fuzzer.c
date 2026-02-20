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
 * Fuzzer targeting VACM (View-based Access Control Model) configuration
 * parsing functions. These parse access control rules from config lines.
 * Bugs here can lead to authorization bypass or memory corruption when
 * processing malicious configuration.
 *
 * The VACM parsers expect structured config lines with space-separated
 * numeric fields followed by octet-string fields. We construct valid
 * config line skeletons from fuzz data to avoid trivial NULL-deref
 * crashes in skip_token_const/atoi, while still fuzzing the numeric
 * values, string contents, and field lengths.
 *
 * Targets: vacm_parse_config_view, vacm_parse_config_access,
 *          vacm_parse_config_auth_access, vacm_parse_config_group
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/library/vacm.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
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
    if (size < 8)
        return 0;

    /* Use first byte as selector, next bytes as numeric field values */
    uint8_t selector = data[0];
    data++;
    size--;

    /*
     * Build structured config lines from fuzz data.
     *
     * Each parser expects a specific number of leading integer fields
     * (parsed via atoi + skip_token_const) followed by octet-string
     * fields. We use fuzz bytes for the integer values and append the
     * remaining fuzz data as a raw string suffix for the string fields.
     */
    char line[4096];
    char *suffix;
    size_t suffix_len;

    switch (selector % 4) {
    case 0:
        /*
         * vacm_parse_config_view expects:
         *   <status> <storageType> <viewType> <viewName> <subtree> <mask>
         * 3 integer fields, then octet-string / OID / octet-string.
         */
        if (size < 3)
            return 0;
        suffix_len = size - 3;
        suffix = strndup((const char *)data + 3, suffix_len);
        if (!suffix)
            return 0;
        snprintf(line, sizeof(line), "%d %d %d %s",
                 (int)data[0], (int)data[1], (int)data[2], suffix);
        free(suffix);
        vacm_parse_config_view("view", line);
        break;

    case 1:
        /*
         * vacm_parse_config_access expects:
         *   <status> <storageType> <secModel> <secLevel> <match>
         *   <groupName> <contextPrefix> <readView> <writeView> <notifyView>
         * 5 integer fields, then octet-string fields.
         */
        if (size < 5)
            return 0;
        suffix_len = size - 5;
        suffix = strndup((const char *)data + 5, suffix_len);
        if (!suffix)
            return 0;
        snprintf(line, sizeof(line), "%d %d %d %d %d %s",
                 (int)data[0], (int)data[1], (int)data[2],
                 (int)data[3], (int)data[4], suffix);
        free(suffix);
        vacm_parse_config_access("access", line);
        break;

    case 2:
        /*
         * vacm_parse_config_auth_access expects:
         *   (same 5 integer fields as access)
         *   <groupName> <contextPrefix> <authtype> <view>
         */
        if (size < 5)
            return 0;
        suffix_len = size - 5;
        suffix = strndup((const char *)data + 5, suffix_len);
        if (!suffix)
            return 0;
        snprintf(line, sizeof(line), "%d %d %d %d %d %s",
                 (int)data[0], (int)data[1], (int)data[2],
                 (int)data[3], (int)data[4], suffix);
        free(suffix);
        vacm_parse_config_auth_access("authaccess", line);
        break;

    case 3:
        /*
         * vacm_parse_config_group expects:
         *   <status> <storageType> <secModel> <securityName> <groupName>
         * 3 integer fields, then octet-string fields.
         */
        if (size < 3)
            return 0;
        suffix_len = size - 3;
        suffix = strndup((const char *)data + 3, suffix_len);
        if (!suffix)
            return 0;
        snprintf(line, sizeof(line), "%d %d %d %s",
                 (int)data[0], (int)data[1], (int)data[2], suffix);
        free(suffix);
        vacm_parse_config_group("group", line);
        break;
    }

    /* Clean up any state created by the config parsers */
    vacm_destroyAllGroupEntries();
    vacm_destroyAllAccessEntries();
    vacm_destroyAllViewEntries();

    return 0;
}
