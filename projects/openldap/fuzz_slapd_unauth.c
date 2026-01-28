/*
 * Harness: fuzz_slapd_unauth
 *
 * TIER:    1 (Server-Exploitable - High Priority)
 * TESTS:   slapd network message reception (unauthenticated context)
 * PATH:    Network -> Sockbuf -> ber_get_next() -> message parsing
 * CONFIG:  sb_max_incoming = 262143 (256KB - unauthenticated default)
 *
 * BUGS FOUND HERE ARE SERVER-EXPLOITABLE
 *
 * This harness simulates the exact code path used by slapd when
 * receiving LDAP messages from the network. It includes all
 * production security checks:
 *
 * 1. Data arrives via Sockbuf (socket abstraction)
 * 2. ber_get_next() reads and validates framing against sb_max_incoming
 * 3. Message is parsed with ber_scanf()
 *
 * This is the PRIMARY harness for finding exploitable vulnerabilities
 * in OpenLDAP's network-facing code.
 *
 * Reference: servers/slapd/slap.h defines SLAP_MAX_INCOMING
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <lber.h>

/* Memory-backed Sockbuf I/O handlers */
struct mem_buffer {
    const uint8_t *data;
    size_t size;
    size_t pos;
};

static int sb_mem_setup(Sockbuf_IO_Desc *sbiod, void *arg) {
    sbiod->sbiod_pvt = arg;
    return 0;
}

static int sb_mem_remove(Sockbuf_IO_Desc *sbiod) {
    return 0;
}

static ber_slen_t sb_mem_read(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len) {
    struct mem_buffer *mb = sbiod->sbiod_pvt;
    size_t remaining = mb->size - mb->pos;
    size_t to_read = (len < remaining) ? len : remaining;

    if (to_read == 0) {
        return 0;  /* EOF */
    }

    memcpy(buf, mb->data + mb->pos, to_read);
    mb->pos += to_read;
    return to_read;
}

static ber_slen_t sb_mem_write(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len) {
    return len;  /* Discard writes */
}

static int sb_mem_ctrl(Sockbuf_IO_Desc *sbiod, int opt, void *arg) {
    return 0;
}

static int sb_mem_close(Sockbuf_IO_Desc *sbiod) {
    return 0;
}

static Sockbuf_IO sb_mem_io = {
    sb_mem_setup,
    sb_mem_remove,
    sb_mem_ctrl,
    sb_mem_read,
    sb_mem_write,
    sb_mem_close
};

/* Maximum incoming message size (matches slapd default) */
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

    /* Set up memory buffer as socket input */
    mb.data = data;
    mb.size = size;
    mb.pos = 0;

    /* Create Sockbuf - this is what slapd uses for network I/O */
    sb = ber_sockbuf_alloc();
    if (!sb) return 0;

    ber_sockbuf_add_io(sb, &sb_mem_io, LBER_SBIOD_LEVEL_PROVIDER, &mb);

    /* Set max incoming size - THIS IS CRITICAL for security!
     * slapd sets this to 262143 (256KB-1) for unauthenticated connections.
     * Without this, ber_get_next() will allocate whatever the BER length says.
     */
    {
        ber_len_t max = MAX_INCOMING_SIZE;
        ber_sockbuf_ctrl(sb, LBER_SB_OPT_SET_MAX_INCOMING, &max);
    }

    /* Allocate BerElement for incoming message */
    ber = ber_alloc_t(LBER_USE_DER);
    if (!ber) {
        ber_sockbuf_free(sb);
        return 0;
    }

    /* =============================================
     * THIS IS THE ACTUAL SERVER ENTRY POINT
     * =============================================
     * ber_get_next() is called by connection_input() in slapd.
     * It reads the BER tag and length, validates framing,
     * then reads the complete message into the BerElement.
     */
    tag = ber_get_next(sb, &len, ber);

    if (tag == LBER_ERROR) {
        /* Malformed at framing level - expected for most fuzz input */
        goto cleanup;
    }

    /* Successfully framed a message - now parse it */

    /* =============================================
     * Parse LDAP message envelope
     * =============================================
     * LDAPMessage ::= SEQUENCE {
     *     messageID   INTEGER,
     *     protocolOp  CHOICE { ... },
     *     controls    [0] Controls OPTIONAL
     * }
     */
    tag = ber_scanf(ber, "{it", &msgid, &tag);
    if (tag == LBER_ERROR) {
        goto cleanup;
    }

    /* Parse based on operation type */
    switch (tag) {
        case 0x60:  /* BindRequest */
            {
                ber_int_t version;
                struct berval name, cred;
                ber_tag_t auth_tag;

                tag = ber_scanf(ber, "{im" /* version, name */,
                               &version, &name);
                if (tag != LBER_ERROR) {
                    /* Read authentication choice */
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
                    /* Parse filter - this is where many bugs live */
                    ber_tag_t filter_tag;
                    ber_len_t filter_len;
                    filter_tag = ber_peek_tag(ber, &filter_len);

                    /* Skip filter for now - full parsing needs slapd */
                    struct berval filter_ber;
                    ber_skip_element(ber, &filter_ber);

                    /* Skip attribute list - just skip the element */
                    struct berval attrs_ber;
                    ber_skip_element(ber, &attrs_ber);
                }
            }
            break;

        case 0x42:  /* UnbindRequest */
            /* No content to parse */
            break;

        case 0x50:  /* AbandonRequest */
            {
                ber_int_t abandon_id;
                ber_scanf(ber, "i", &abandon_id);
            }
            break;

        default:
            /* Other operations - skip body */
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
