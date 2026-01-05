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

/*
 * FuzzDataConversion - Tests pure data conversion functions
 * Stateless harness that operates on memory buffers without network setup
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <modbus.h>

#define kMinInputLength 5
#define kMaxInputLength 512

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < kMinInputLength || size > kMaxInputLength) {
        return 0;
    }

    uint8_t op = data[0] % 13;
    const uint8_t *buf = data + 1;
    size_t buf_size = size - 1;

    uint16_t regs[128];
    uint8_t bits[256];
    float result = 0.0f;

    memset(regs, 0, sizeof(regs));
    memset(bits, 0, sizeof(bits));

    /* Copy fuzz data to registers array */
    if (buf_size >= 4) {
        size_t copy_size = (buf_size > sizeof(regs)) ? sizeof(regs) : buf_size;
        memcpy(regs, buf, copy_size);
    }

    switch (op) {
        case 0:
            /* modbus_get_float_abcd - Big-endian float */
            if (buf_size >= 4) {
                result = modbus_get_float_abcd(regs);
            }
            break;

        case 1:
            /* modbus_get_float_badc - Big-endian with byte swap in word */
            if (buf_size >= 4) {
                result = modbus_get_float_badc(regs);
            }
            break;

        case 2:
            /* modbus_get_float_cdab - Little-endian with word swap */
            if (buf_size >= 4) {
                result = modbus_get_float_cdab(regs);
            }
            break;

        case 3:
            /* modbus_get_float_dcba - Little-endian float */
            if (buf_size >= 4) {
                result = modbus_get_float_dcba(regs);
            }
            break;

        case 4:
            /* modbus_set_float_abcd */
            if (buf_size >= 4) {
                float f;
                memcpy(&f, buf, sizeof(float));
                modbus_set_float_abcd(f, regs);
            }
            break;

        case 5:
            /* modbus_set_float_badc */
            if (buf_size >= 4) {
                float f;
                memcpy(&f, buf, sizeof(float));
                modbus_set_float_badc(f, regs);
            }
            break;

        case 6:
            /* modbus_set_float_cdab */
            if (buf_size >= 4) {
                float f;
                memcpy(&f, buf, sizeof(float));
                modbus_set_float_cdab(f, regs);
            }
            break;

        case 7:
            /* modbus_set_float_dcba */
            if (buf_size >= 4) {
                float f;
                memcpy(&f, buf, sizeof(float));
                modbus_set_float_dcba(f, regs);
            }
            break;

        case 8:
            /* modbus_set_bits_from_byte - Set 8 bits from a single byte */
            if (buf_size >= 1) {
                modbus_set_bits_from_byte(bits, 0, buf[0]);
            }
            break;

        case 9:
            /* modbus_set_bits_from_bytes - Set multiple bits from byte array */
            if (buf_size >= 2) {
                int nb_bits = (buf_size - 1) * 8;
                if (nb_bits > 256) nb_bits = 256;
                modbus_set_bits_from_bytes(bits, 0, nb_bits, buf);
            }
            break;

        case 10:
            /* modbus_get_byte_from_bits - Get byte from 8 bits */
            if (buf_size >= 8) {
                /* First populate bits array */
                memcpy(bits, buf, (buf_size > 256) ? 256 : buf_size);
                int idx = buf[0] % 64;
                (void)modbus_get_byte_from_bits(bits, idx, 8);
            }
            break;

        case 11:
            /* Combined test: set float then get it back */
            if (buf_size >= 4) {
                float f;
                memcpy(&f, buf, sizeof(float));
                modbus_set_float_abcd(f, regs);
                result = modbus_get_float_abcd(regs);
            }
            break;

        case 12:
            /* Combined test: set bits then get byte */
            if (buf_size >= 2) {
                int nb_bits = (buf_size > 32) ? 32 : (int)buf_size;
                modbus_set_bits_from_bytes(bits, 0, nb_bits * 8, buf);
                (void)modbus_get_byte_from_bits(bits, 0, 8);
            }
            break;
    }

    /* Prevent unused variable warning */
    (void)result;

    return 0;
}
