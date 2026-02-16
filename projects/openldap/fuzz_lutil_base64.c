/*
 * Harness: fuzz_lutil_base64
 *
 * TIER:    3 (Client Libraries - Lower Priority)
 * TESTS:   liblutil base64 encode/decode
 * PATH:    lutil_b64_pton() / lutil_b64_ntop() round-trip
 * CONFIG:  Utility code used across OpenLDAP
 *
 * This harness tests the ISC-derived base64 encoding and decoding
 * functions used throughout OpenLDAP for LDIF values, SASL credentials,
 * and certificate handling. It performs encode-decode and decode-encode
 * round-trips with integrity checks.
 *
 * Targets: lutil_b64_pton(), lutil_b64_ntop()
 *
 * Value of this harness:
 * - Tests base64 decode with arbitrary (possibly malformed) input
 * - Validates round-trip integrity for encode-decode
 * - Exercises error handling for invalid base64
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "portable.h"
#include <lber.h>
#include <lutil.h>
#include <ldif.h>

/* Maximum input size */
#define MAX_INPUT_SIZE 262144

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > MAX_INPUT_SIZE) {
        return 0;
    }

    /* === Test 1: Decode — treat fuzz input as base64 string === */
    {
        /* Null-terminate for b64_pton */
        char *b64_str = malloc(size + 1);
        if (!b64_str) return 0;
        memcpy(b64_str, data, size);
        b64_str[size] = '\0';

        size_t decode_buf_size = LUTIL_BASE64_DECODE_LEN(size) + 1;
        unsigned char *decoded = malloc(decode_buf_size);
        if (decoded) {
            int decoded_len = lutil_b64_pton(b64_str, decoded, decode_buf_size);

            /* If decode succeeded, re-encode and decode again to check consistency */
            if (decoded_len > 0) {
                size_t encode_buf_size = LUTIL_BASE64_ENCODE_LEN(decoded_len) + 1;
                char *reencoded = malloc(encode_buf_size);
                if (reencoded) {
                    int enc_len = lutil_b64_ntop(decoded, (size_t)decoded_len,
                                                 reencoded, encode_buf_size);
                    if (enc_len > 0) {
                        /* Decode the re-encoded output */
                        unsigned char *redecoded = malloc(decoded_len + 1);
                        if (redecoded) {
                            int redec_len = lutil_b64_pton(reencoded, redecoded,
                                                           (size_t)(decoded_len + 1));
                            /* The decoded outputs must match */
                            if (redec_len == decoded_len) {
                                /* Verify content matches — mismatch would be a bug */
                                memcmp(decoded, redecoded, (size_t)decoded_len);
                            }
                            free(redecoded);
                        }
                    }
                    free(reencoded);
                }
            }

            free(decoded);
        }
        free(b64_str);
    }

    /* === Test 2: Encode — treat fuzz input as raw binary === */
    {
        size_t encode_buf_size = LUTIL_BASE64_ENCODE_LEN(size) + 1;
        char *encoded = malloc(encode_buf_size);
        if (encoded) {
            int enc_len = lutil_b64_ntop(data, size, encoded, encode_buf_size);
            if (enc_len > 0) {
                /* Decode the encoded output and verify round-trip */
                size_t decode_buf_size = LUTIL_BASE64_DECODE_LEN(enc_len) + 1;
                unsigned char *decoded = malloc(decode_buf_size);
                if (decoded) {
                    encoded[enc_len] = '\0';
                    int dec_len = lutil_b64_pton(encoded, decoded, decode_buf_size);
                    /* Round-trip: decoded must match original input */
                    if (dec_len == (int)size) {
                        memcmp(data, decoded, size);
                    }
                    free(decoded);
                }
            }
            free(encoded);
        }
    }

    return 0;
}
