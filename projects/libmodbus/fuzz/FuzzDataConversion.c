/* Copyright 2024 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* FuzzDataConversion.c - Direct API surface for data conversion utilities
 *
 * Attack model: Application processes register data received from the network
 * using the libmodbus data conversion API. The register content is
 * attacker-controlled (e.g., malicious Modbus server/device, MITM).
 *
 * This is a pure in-process harness — no sockets, no threads, no select().
 * Exercises:
 *   - modbus_get_float_{abcd,dcba,badc,cdab}  (vuln1: byte << 24 overflow)
 *   - modbus_set_float_{abcd,dcba,badc,cdab}  (vuln3: strict aliasing)
 *   - MODBUS_GET_INT32_FROM_INT16              (vuln2: signed cast + shift)
 *   - MODBUS_GET_INT64_FROM_INT16              (vuln2: signed cast + shift)
 *   - MODBUS_GET_INT16_FROM_INT8               (vuln2: signed cast + shift)
 *   - MODBUS_SET_INT32_TO_INT16                (right-shift of negative)
 *   - MODBUS_SET_INT64_TO_INT16                (right-shift of negative)
 *   - MODBUS_SET_INT16_TO_INT8                 (right-shift of negative)
 *   - modbus_set_bits_from_byte / modbus_get_byte_from_bits
 *   - Round-trip: get_float → set_float (detects miscompilation from aliasing UB)
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <modbus.h>

/* Sinks to prevent compiler from optimizing away calls */
static volatile float g_float_sink[4];
static volatile int32_t g_int32_sink;
static volatile int64_t g_int64_sink;
static volatile int16_t g_int16_sink;
static volatile uint8_t g_byte_sink;

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8)
        return 0; /* Need at least 4 uint16_t registers */

    /* --- Float conversions (get) --- */
    /* Interpret fuzz data as an array of registers */
    uint16_t regs[4];
    memcpy(regs, data, 8);

    g_float_sink[0] = modbus_get_float_abcd(regs);
    g_float_sink[1] = modbus_get_float_dcba(regs);
    g_float_sink[2] = modbus_get_float_badc(regs);
    g_float_sink[3] = modbus_get_float_cdab(regs);

    /* --- Float conversions (set) — vuln3 location --- */
    /* Use fuzz-derived float for set operations.
     * Reinterpret first 4 bytes as a float bit pattern. */
    float fuzz_float;
    memcpy(&fuzz_float, data, sizeof(float));

    uint16_t float_dest[2];
    modbus_set_float_abcd(fuzz_float, float_dest);
    modbus_set_float_dcba(fuzz_float, float_dest);
    modbus_set_float_badc(fuzz_float, float_dest);
    modbus_set_float_cdab(fuzz_float, float_dest);

    /* --- Round-trip: get_float → set_float --- */
    /* This can detect miscompilation from vuln3's strict aliasing violation
     * under -O2 -fstrict-aliasing. */
    uint16_t rt_dest[2];
    modbus_set_float_abcd(g_float_sink[0], rt_dest);
    modbus_set_float_dcba(g_float_sink[1], rt_dest);
    modbus_set_float_badc(g_float_sink[2], rt_dest);
    modbus_set_float_cdab(g_float_sink[3], rt_dest);

    /* --- Integer conversion macros (GET) --- */
    /* MODBUS_GET_INT32_FROM_INT16 — vuln2 pattern */
    g_int32_sink = MODBUS_GET_INT32_FROM_INT16(regs, 0);

    /* MODBUS_SET_INT32_TO_INT16 round-trip */
    uint16_t dest32[2];
    MODBUS_SET_INT32_TO_INT16(dest32, 0, g_int32_sink);

    /* MODBUS_GET_INT16_FROM_INT8 — vuln2 pattern, never previously fuzzed */
    g_int16_sink = MODBUS_GET_INT16_FROM_INT8(data, 0);

    /* MODBUS_SET_INT16_TO_INT8 round-trip */
    uint8_t dest8[2];
    MODBUS_SET_INT16_TO_INT8(dest8, 0, g_int16_sink);

    /* --- 64-bit conversions (need 16 bytes for diverse input) --- */
    if (size >= 16) {
        uint16_t regs64[8];
        memcpy(regs64, data, 16);

        g_int64_sink = MODBUS_GET_INT64_FROM_INT16(regs64, 0);

        uint16_t dest64[4];
        MODBUS_SET_INT64_TO_INT16(dest64, 0, g_int64_sink);
    }

    /* --- Bit utilities --- */
    uint8_t bits[8];
    modbus_set_bits_from_byte(bits, 0, data[0]);

    /* Exercise modbus_get_byte_from_bits with edge-case nb_bits.
     * data[1] % 9 gives 0–8, exercising the assert/clamp path. */
    g_byte_sink = modbus_get_byte_from_bits(bits, 0, (data[1] % 9));

    /* Exercise modbus_set_bits_from_bytes with varying nb_bits */
    if (size >= 10) {
        uint8_t bits_out[64];
        unsigned int nb_bits = data[8];
        if (nb_bits > 64) nb_bits = 64;
        if (nb_bits > 0) {
            unsigned int nb_bytes_needed = (nb_bits + 7) / 8;
            if (size >= 9 + nb_bytes_needed) {
                modbus_set_bits_from_bytes(bits_out, 0, nb_bits, data + 9);
            }
        }
    }

    return 0;
}
