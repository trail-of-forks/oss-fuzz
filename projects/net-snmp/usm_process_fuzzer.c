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
 * Fuzzer targeting USM (User-based Security Model) message processing.
 * Unlike snmp_parse_fuzzer which stubs out the security module, this
 * harness registers the real USM security module via init_usm() so that
 * usm_process_in_msg(), usm_parse_security_parameters(), and related
 * functions are exercised with attacker-controlled SNMPv3 packets.
 *
 * This targets the most security-critical code path in net-snmp:
 * authentication, time validation, and decryption of incoming packets.
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

static int initialized = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    if (getenv("NETSNMP_DEBUGGING") != NULL) {
        snmp_enable_stderrlog();
        snmp_set_do_debugging(1);
        debug_register_tokens("");
    }

    /*
     * Suppress config file reads and state persistence to avoid
     * filesystem side effects during fuzzing.
     */
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_DISABLE_CONFIG_LOAD, 1);

    /*
     * Initialize the USM security module. This registers the real
     * usm_secmod_process_in_msg as the decode callback for security
     * model 3 (USM), so snmpv3_parse() will dispatch into USM code.
     */
    init_snmp("usm_fuzzer");
    initialized = 1;

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!initialized || size == 0)
        return 0;

    size_t bytes_remaining = size;
    netsnmp_pdu *pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);
    if (!pdu)
        return 0;

    netsnmp_session sess;
    memset(&sess, 0, sizeof(sess));
    sess.version = SNMP_VERSION_3;
    sess.securityModel = SNMP_SEC_MODEL_USM;

    /*
     * Call snmpv3_parse with the real USM module registered.
     * This will parse the SNMPv3 header, extract the security
     * parameters, and dispatch to usm_process_in_msg() which
     * handles authentication, timeliness, and decryption.
     */
    snmpv3_parse(pdu, NETSNMP_REMOVE_CONST(u_char *, data),
                 &bytes_remaining, NULL, &sess);

    snmp_free_pdu(pdu);
    return 0;
}
