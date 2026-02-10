/*
 * validate_unicode_crash - Triage tool for liblunicode fuzzer crashes
 *
 * Classifies crash inputs into severity tiers:
 *
 *   Tier 1: Input passes UTF8StringValidate() -> directly exploitable
 *           via any LDAP search filter, DN, or attribute value sent to slapd
 *
 *   Tier 2: Input fails UTF8StringValidate() -> slapd would reject before
 *           normalization, but still a real bug reachable through non-standard
 *           callers (contrib overlays, third-party code)
 *
 * Usage: validate_unicode_crash <crash_file> [crash_file ...]
 *
 * The UTF8StringValidate() implementation is extracted from
 * servers/slapd/schema_init.c to avoid requiring a full slapd build.
 */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <lber.h>
#include <ldap_pvt_uc.h>

/*
 * UTF-8 character length from first byte.
 * Reimplements LDAP_UTF8_CHARLEN2 from OpenLDAP.
 */
static int utf8_charlen(unsigned char c) {
    if (c < 0x80) return 1;
    if ((c & 0xe0) == 0xc0) return 2;
    if ((c & 0xf0) == 0xe0) return 3;
    if ((c & 0xf8) == 0xf0) return 4;
    if ((c & 0xfc) == 0xf8) return 5;
    if ((c & 0xfe) == 0xfc) return 6;
    return 0; /* invalid */
}

/*
 * Reimplementation of UTF8StringValidate() from servers/slapd/schema_init.c
 *
 * This is the validator slapd runs BEFORE calling UTF8bvnormalize().
 * It checks basic UTF-8 well-formedness but notably does NOT check for:
 *   - Overlong sequences
 *   - Surrogates (U+D800-U+DFFF)
 *   - Codepoints above U+10FFFF
 *
 * Returns 0 on success (valid), -1 on failure (invalid).
 */
static int utf8_string_validate(const uint8_t *data, size_t len) {
    unsigned char *u = (unsigned char *)data;
    size_t count;
    int charlen;

    /* Empty directoryString is invalid in slapd */
    if (len == 0) return -1;

    for (count = len; count > 0; count -= charlen, u += charlen) {
        charlen = utf8_charlen(*u);

        /* Check that charlen fits in remaining data */
        if (charlen == 0 || (size_t)charlen > count) {
            return -1;
        }

        /* Verify continuation bytes (fall-through is intentional) */
        switch (charlen) {
            case 6:
                if ((u[5] & 0xc0) != 0x80) return -1;
                /* fall through */
            case 5:
                if ((u[4] & 0xc0) != 0x80) return -1;
                /* fall through */
            case 4:
                if ((u[3] & 0xc0) != 0x80) return -1;
                /* fall through */
            case 3:
                if ((u[2] & 0xc0) != 0x80) return -1;
                /* fall through */
            case 2:
                if ((u[1] & 0xc0) != 0x80) return -1;
                /* fall through */
            case 1:
                break;
            default:
                return -1;
        }
    }

    if (count != 0) return -1;

    return 0;
}

static int process_file(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open %s\n", filename);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        fprintf(stderr, "ERROR: Empty file %s\n", filename);
        fclose(f);
        return -1;
    }

    uint8_t *data = malloc(fsize);
    if (!data) {
        fclose(f);
        return -1;
    }

    if (fread(data, 1, fsize, f) != (size_t)fsize) {
        fprintf(stderr, "ERROR: Short read on %s\n", filename);
        free(data);
        fclose(f);
        return -1;
    }
    fclose(f);

    printf("=== %s (%ld bytes) ===\n", filename, fsize);

    /* Print hex dump of first 64 bytes */
    printf("  Hex: ");
    int dump_len = fsize < 64 ? fsize : 64;
    for (int i = 0; i < dump_len; i++) {
        printf("%02x", data[i]);
        if (i % 4 == 3) printf(" ");
    }
    if (fsize > 64) printf("...");
    printf("\n");

    /* Step 1: UTF8StringValidate */
    int valid = utf8_string_validate(data, fsize);
    printf("  UTF8StringValidate: %s\n", valid == 0 ? "PASS" : "FAIL");

    /* Step 2: UTF8bvnormalize with each flag */
    struct berval input = { .bv_len = fsize, .bv_val = (char *)data };
    struct berval output = { 0 };
    struct berval *result;

    const char *flag_names[] = { "NOCASEFOLD", "CASEFOLD", "APPROX" };
    unsigned flags[] = { LDAP_UTF8_NOCASEFOLD, LDAP_UTF8_CASEFOLD, LDAP_UTF8_APPROX };

    if (valid == 0) {
        /* Input passes validation — slapd WOULD call UTF8bvnormalize on this.
         * If it crashes here, this is a Tier 1 server-exploitable bug. */
        for (int i = 0; i < 3; i++) {
            memset(&output, 0, sizeof(output));
            result = UTF8bvnormalize(&input, &output, flags[i], NULL);
            if (result) {
                printf("  UTF8bvnormalize(%s): OK (%lu bytes)\n",
                       flag_names[i], (unsigned long)output.bv_len);
                ber_memfree(output.bv_val);
            } else {
                printf("  UTF8bvnormalize(%s): REJECTED\n", flag_names[i]);
            }
        }
    } else {
        /* Input fails validation — slapd would reject before normalizing.
         * Skip UTF8bvnormalize to avoid triggering known OOB reads on
         * malformed input (which is the bug we're triaging). */
        printf("  UTF8bvnormalize: SKIPPED (input fails validation)\n");
    }

    /* Classification */
    if (valid == 0) {
        printf("  TIER 1: Server-exploitable! Input passes slapd validation.\n");
        printf("    -> Reachable via any LDAP search filter, DN, or attribute value\n");
    } else {
        printf("  TIER 2: Library bug. Input fails slapd validation.\n");
        printf("    -> Reachable through contrib overlays or third-party callers\n");
    }

    printf("\n");
    free(data);

    return valid == 0 ? 1 : 2;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <crash_file> [crash_file ...]\n", argv[0]);
        fprintf(stderr, "\nClassifies liblunicode fuzzer crashes into severity tiers.\n");
        return 1;
    }

    int tier1_count = 0;
    int tier2_count = 0;
    int error_count = 0;

    for (int i = 1; i < argc; i++) {
        int tier = process_file(argv[i]);
        if (tier == 1) tier1_count++;
        else if (tier == 2) tier2_count++;
        else error_count++;
    }

    printf("=== SUMMARY ===\n");
    printf("  Tier 1 (server-exploitable): %d\n", tier1_count);
    printf("  Tier 2 (library bug):        %d\n", tier2_count);
    printf("  Errors:                       %d\n", error_count);

    /* Exit non-zero if any Tier 1 crashes found */
    return tier1_count > 0 ? 1 : 0;
}
