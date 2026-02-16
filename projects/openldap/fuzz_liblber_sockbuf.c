/*
 * Harness: fuzz_liblber_sockbuf
 *
 * TIER:    2 (BER wire-format parsing, shared between client and server)
 * TESTS:   BER framing and LDAP message parsing via Sockbuf I/O layer
 * PATH:    Sockbuf -> ber_get_next() -> ber_scanf() message parsing
 * CONFIG:  sb_max_incoming = 262143 (256KB - matches slapd unauthenticated default)
 *
 * Tests BER framing and decoding through Sockbuf, which is the I/O
 * layer shared by slapd and libldap clients. Exercises ber_get_next()
 * with the unauthenticated message size limit, then parses the LDAP
 * message envelope and common operation types.
 *
 * Note: This harness links against libldap/liblber client libraries.
 * slapd server code (do_bind, do_search, get_filter0, etc.) is NOT
 * compiled or tested here — that requires --enable-slapd in the build.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include <lber.h>

#include "sockbuf_mem.h"

/* Maximum incoming message size (matches slapd unauthenticated default) */
#define MAX_INCOMING_SIZE (262143)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Sockbuf *sb = NULL;
    BerElement *ber = NULL;
    struct mem_buffer mb;
    ber_tag_t tag;
    ber_len_t len;
    ber_int_t msgid;

    if (size == 0 || size > MAX_INCOMING_SIZE) {
        return 0;
    }

    mb.data = data;
    mb.size = size;
    mb.pos = 0;

    sb = ber_sockbuf_alloc();
    if (!sb) return 0;

    ber_sockbuf_add_io(sb, &sb_mem_io, LBER_SBIOD_LEVEL_PROVIDER, &mb);

    {
        ber_len_t max = MAX_INCOMING_SIZE;
        ber_sockbuf_ctrl(sb, LBER_SB_OPT_SET_MAX_INCOMING, &max);
    }

    ber = ber_alloc_t(LBER_USE_DER);
    if (!ber) {
        ber_sockbuf_free(sb);
        return 0;
    }

    /* Read and validate BER framing via Sockbuf */
    tag = ber_get_next(sb, &len, ber);

    if (tag == LBER_ERROR) {
        goto cleanup;
    }

    /* Parse LDAP message envelope:
     * LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE {...} }
     */
    tag = ber_scanf(ber, "{it", &msgid, &tag);
    if (tag == LBER_ERROR) {
        goto cleanup;
    }

    switch (tag) {
        case 0x60:  /* BindRequest */
            {
                ber_int_t version;
                struct berval name, cred;
                ber_tag_t auth_tag;

                tag = ber_scanf(ber, "{im", &version, &name);
                if (tag != LBER_ERROR) {
                    auth_tag = ber_peek_tag(ber, &len);
                    if (auth_tag == 0x80) {  /* simple auth */
                        ber_scanf(ber, "m}", &cred);
                    }
                }
            }
            break;

        case 0x63:  /* SearchRequest */
            {
                struct berval base;
                ber_int_t scope, deref, sizelimit, timelimit;
                ber_int_t attrsonly;

                tag = ber_scanf(ber, "{miiiib",
                               &base, &scope, &deref,
                               &sizelimit, &timelimit, &attrsonly);

                if (tag != LBER_ERROR) {
                    struct berval filter_ber;
                    ber_skip_element(ber, &filter_ber);

                    struct berval attrs_ber;
                    ber_skip_element(ber, &attrs_ber);
                }
            }
            break;

        case 0x42:  /* UnbindRequest */
            break;

        case 0x50:  /* AbandonRequest */
            {
                ber_int_t abandon_id;
                ber_scanf(ber, "i", &abandon_id);
            }
            break;

        default:
            {
                struct berval body;
                ber_skip_element(ber, &body);
            }
            break;
    }

cleanup:
    if (ber) ber_free(ber, 1);
    if (sb) ber_sockbuf_free(sb);
    return 0;
}
