#!/bin/bash
# generate_seeds.sh - Create seed corpus files for libmodbus fuzzers

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SEEDS_DIR="$SCRIPT_DIR/seeds"

mkdir -p "$SEEDS_DIR/server" "$SEEDS_DIR/client" "$SEEDS_DIR/clientread" "$SEEDS_DIR/rtu" "$SEEDS_DIR/dataconv"

echo "Generating FuzzServer seeds (requests)..."

# FC 0x01: Read Coils - read 37 coils at address 0x0130
echo -ne '\x00\x01\x00\x00\x00\x06\xff\x01\x01\x30\x00\x25' > "$SEEDS_DIR/server/fc01_read_coils.raw"

# FC 0x01: Read max 2000 coils
echo -ne '\x00\x02\x00\x00\x00\x06\x01\x01\x00\x00\x07\xd0' > "$SEEDS_DIR/server/fc01_read_coils_max.raw"

# FC 0x02: Read 22 discrete inputs at address 0x01C4
echo -ne '\x00\x03\x00\x00\x00\x06\xff\x02\x01\xc4\x00\x16' > "$SEEDS_DIR/server/fc02_read_discrete.raw"

# FC 0x03: Read 3 holding registers at address 0x0160
echo -ne '\x00\x04\x00\x00\x00\x06\xff\x03\x01\x60\x00\x03' > "$SEEDS_DIR/server/fc03_read_holding.raw"

# FC 0x03: Read max 125 holding registers
echo -ne '\x00\x05\x00\x00\x00\x06\x01\x03\x00\x00\x00\x7d' > "$SEEDS_DIR/server/fc03_read_holding_max.raw"

# FC 0x04: Read 1 input register at address 0x0108
echo -ne '\x00\x06\x00\x00\x00\x06\xff\x04\x01\x08\x00\x01' > "$SEEDS_DIR/server/fc04_read_input.raw"

# FC 0x05: Write single coil ON at address 0x0130
echo -ne '\x00\x07\x00\x00\x00\x06\xff\x05\x01\x30\xff\x00' > "$SEEDS_DIR/server/fc05_write_coil_on.raw"

# FC 0x05: Write single coil OFF at address 0x0130
echo -ne '\x00\x08\x00\x00\x00\x06\xff\x05\x01\x30\x00\x00' > "$SEEDS_DIR/server/fc05_write_coil_off.raw"

# FC 0x06: Write single register 0x1234 at address 0x0160
echo -ne '\x00\x09\x00\x00\x00\x06\xff\x06\x01\x60\x12\x34' > "$SEEDS_DIR/server/fc06_write_register.raw"

# FC 0x07: Read exception status
echo -ne '\x00\x0a\x00\x00\x00\x02\xff\x07' > "$SEEDS_DIR/server/fc07_read_exc_status.raw"

# FC 0x0F: Write 8 coils at address 0x0130
echo -ne '\x00\x0b\x00\x00\x00\x09\xff\x0f\x01\x30\x00\x08\x01\xcd' > "$SEEDS_DIR/server/fc0f_write_coils.raw"

# FC 0x10: Write 3 registers at address 0x0160
echo -ne '\x00\x0c\x00\x00\x00\x0d\xff\x10\x01\x60\x00\x03\x06\x02\x2b\x00\x01\x00\x64' > "$SEEDS_DIR/server/fc10_write_registers.raw"

# FC 0x11: Report slave ID
echo -ne '\x00\x0d\x00\x00\x00\x02\xff\x11' > "$SEEDS_DIR/server/fc11_report_slave_id.raw"

# FC 0x16: Mask write register at address 0x0160
echo -ne '\x00\x0e\x00\x00\x00\x08\xff\x16\x01\x60\x00\xf2\x00\x25' > "$SEEDS_DIR/server/fc16_mask_write.raw"

# FC 0x17: Write and read registers
echo -ne '\x00\x0f\x00\x00\x00\x11\xff\x17\x01\x60\x00\x03\x01\x60\x00\x02\x04\x00\x01\x00\x02' > "$SEEDS_DIR/server/fc17_write_and_read.raw"

# FC 0x05 with invalid coil value (should trigger error)
echo -ne '\x00\x10\x00\x00\x00\x06\xff\x05\x01\x30\x12\x34' > "$SEEDS_DIR/server/fc05_invalid_value.raw"

# Unknown function code 0x99
echo -ne '\x00\x11\x00\x00\x00\x06\xff\x99\x00\x00\x00\x01' > "$SEEDS_DIR/server/fc_unknown.raw"

echo "Generating FuzzClient seeds (responses)..."

# FC 0x01 response: 5 bytes of coil data
echo -ne '\x00\x01\x00\x00\x00\x08\xff\x01\x05\xcd\x6b\xb2\x0e\x1b' > "$SEEDS_DIR/client/rsp_fc01_read_coils.raw"

# FC 0x02 response: 3 bytes of discrete input data
echo -ne '\x00\x02\x00\x00\x00\x06\xff\x02\x03\xac\xdb\x35' > "$SEEDS_DIR/client/rsp_fc02_read_discrete.raw"

# FC 0x03 response: 6 bytes (3 registers)
echo -ne '\x00\x03\x00\x00\x00\x09\xff\x03\x06\x02\x2b\x00\x01\x00\x64' > "$SEEDS_DIR/client/rsp_fc03_read_holding.raw"

# FC 0x04 response: 2 bytes (1 register)
echo -ne '\x00\x04\x00\x00\x00\x05\xff\x04\x02\x00\x0a' > "$SEEDS_DIR/client/rsp_fc04_read_input.raw"

# FC 0x05 response: echo of write coil ON
echo -ne '\x00\x05\x00\x00\x00\x06\xff\x05\x01\x30\xff\x00' > "$SEEDS_DIR/client/rsp_fc05_write_coil.raw"

# FC 0x06 response: echo of write register
echo -ne '\x00\x06\x00\x00\x00\x06\xff\x06\x01\x60\x12\x34' > "$SEEDS_DIR/client/rsp_fc06_write_register.raw"

# FC 0x0F response: write coils confirmation
echo -ne '\x00\x07\x00\x00\x00\x06\xff\x0f\x01\x30\x00\x08' > "$SEEDS_DIR/client/rsp_fc0f_write_coils.raw"

# FC 0x10 response: write registers confirmation
echo -ne '\x00\x08\x00\x00\x00\x06\xff\x10\x01\x60\x00\x03' > "$SEEDS_DIR/client/rsp_fc10_write_regs.raw"

# FC 0x11 response: Report slave ID
echo -ne '\x00\x09\x00\x00\x00\x12\xff\x11\x0f\xb4\xff\x4c\x4d\x42\x33\x2e\x31\x2e\x31\x30\x00\x00\x00' > "$SEEDS_DIR/client/rsp_fc11_report_slave.raw"

# FC 0x16 response: mask write echo
echo -ne '\x00\x0a\x00\x00\x00\x08\xff\x16\x01\x60\x00\xf2\x00\x25' > "$SEEDS_DIR/client/rsp_fc16_mask_write.raw"

# FC 0x17 response: write/read response
echo -ne '\x00\x0b\x00\x00\x00\x09\xff\x17\x06\x02\x2b\x00\x01\x00\x64' > "$SEEDS_DIR/client/rsp_fc17_write_and_read.raw"

# Exception responses
echo -ne '\x00\x0c\x00\x00\x00\x03\xff\x81\x01' > "$SEEDS_DIR/client/rsp_exc_illegal_func.raw"
echo -ne '\x00\x0d\x00\x00\x00\x03\xff\x81\x02' > "$SEEDS_DIR/client/rsp_exc_illegal_addr.raw"
echo -ne '\x00\x0e\x00\x00\x00\x03\xff\x81\x03' > "$SEEDS_DIR/client/rsp_exc_illegal_value.raw"
echo -ne '\x00\x0f\x00\x00\x00\x03\xff\x81\x04' > "$SEEDS_DIR/client/rsp_exc_server_failure.raw"

echo "Generating FuzzClientRead seeds (read operations with fuzzable payload)..."

# FuzzClientRead seed format:
# Byte 0: op selector (% 4 -> FC 0x01, 0x02, 0x03, 0x04)
# Byte 1: quantity
# Byte 2+: response payload data to fuzz

# FC 0x01 - Read Coils (op=0)
echo -ne '\x00\x0a' > "$SEEDS_DIR/clientread/read_coils_10.raw"
echo -ne '\x00\x20\xff\xff\xaa\x55' > "$SEEDS_DIR/clientread/read_coils_32.raw"
echo -ne '\x00\x08\xcd' > "$SEEDS_DIR/clientread/read_coils_8.raw"

# FC 0x02 - Read Discrete Inputs (op=1)
echo -ne '\x01\x10\xac\xdb\x35' > "$SEEDS_DIR/clientread/read_discrete_16.raw"
echo -ne '\x01\x18\xff\x00\xff' > "$SEEDS_DIR/clientread/read_discrete_24.raw"

# FC 0x03 - Read Holding Registers (op=2)
echo -ne '\x02\x05\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44' > "$SEEDS_DIR/clientread/read_holding_5.raw"
echo -ne '\x02\x03\x02\x2b\x00\x01\x00\x64' > "$SEEDS_DIR/clientread/read_holding_3.raw"
echo -ne '\x02\x01\x12\x34' > "$SEEDS_DIR/clientread/read_holding_1.raw"

# FC 0x04 - Read Input Registers (op=3)
echo -ne '\x03\x0a\x00\x0a\x00\x14\x00\x1e' > "$SEEDS_DIR/clientread/read_input_10.raw"
echo -ne '\x03\x02\xde\xad\xbe\xef' > "$SEEDS_DIR/clientread/read_input_2.raw"

# Edge cases - max quantities
echo -ne '\x00\xc8\xff\xff\xff\xff\xff' > "$SEEDS_DIR/clientread/read_coils_max.raw"
echo -ne '\x02\x7d\xaa\xaa\xaa\xaa' > "$SEEDS_DIR/clientread/read_holding_max.raw"

echo "Generating FuzzDataConversion seeds (raw register/byte data)..."

# FuzzDataConversion seed format:
# Bytes 0-7: 4 uint16_t registers (also used as float bits + INT16_FROM_INT8 input)
# Bytes 8+: additional data for set_bits_from_bytes

# All zeros — baseline
echo -ne '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$SEEDS_DIR/dataconv/all_zeros.raw"

# All 0xFF — exercises max byte values in shifts (vuln1: 0xFF << 24)
echo -ne '\xff\xff\xff\xff\xff\xff\xff\xff\x08\xff' > "$SEEDS_DIR/dataconv/all_ff.raw"

# UT_REAL float 123456.00 = 0x47F12000 in ABCD order
echo -ne '\x47\xf1\x20\x00\x47\xf1\x20\x00\x04\xab' > "$SEEDS_DIR/dataconv/ut_real_abcd.raw"

# DCBA byte order
echo -ne '\x00\x20\xf1\x47\x00\x20\xf1\x47\x04\xcd' > "$SEEDS_DIR/dataconv/ut_real_dcba.raw"

# High byte >= 0x80 — triggers vuln1 (signed overflow in byte << 24)
echo -ne '\x80\x00\x00\x00\x80\x00\x00\x00\x04\x55' > "$SEEDS_DIR/dataconv/high_byte_0x80.raw"
echo -ne '\xff\x00\x00\x00\xff\x00\x00\x00\x04\xaa' > "$SEEDS_DIR/dataconv/high_byte_0xff.raw"

# Register value >= 0x8000 — triggers vuln2 (MODBUS_GET_INT32_FROM_INT16 shift)
echo -ne '\x80\x00\x00\x01\x80\x00\x00\x01\x04\x33' > "$SEEDS_DIR/dataconv/reg_0x8000.raw"
echo -ne '\xff\xff\xff\xff\xff\xff\xff\xff\x04\x77' > "$SEEDS_DIR/dataconv/reg_0xffff.raw"

# Negative float NaN patterns
echo -ne '\x7f\xc0\x00\x00\x7f\xc0\x00\x00\x04\x11' > "$SEEDS_DIR/dataconv/nan_pattern.raw"
echo -ne '\xff\x80\x00\x00\xff\x80\x00\x00\x04\x22' > "$SEEDS_DIR/dataconv/neg_inf.raw"

# 64-bit conversion seeds (16+ bytes)
echo -ne '\x80\x00\x00\x01\x00\x00\x00\x01\x80\x00\x00\x01\x00\x00\x00\x01' > "$SEEDS_DIR/dataconv/int64_high.raw"
echo -ne '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' > "$SEEDS_DIR/dataconv/int64_all_ff.raw"

# Bit utility edge cases — nb_bits boundary values
echo -ne '\xaa\x00\x00\x00\x00\x00\x00\x00\x00\xaa' > "$SEEDS_DIR/dataconv/bits_0.raw"
echo -ne '\xaa\x08\x00\x00\x00\x00\x00\x00\x00\xaa' > "$SEEDS_DIR/dataconv/bits_8.raw"

echo "Generating RTU seeds (with CRC)..."

# Helper function to append CRC to RTU message
# CRC-16 table lookup implementation
append_crc() {
    local input="$1"
    local output="$2"
    # Write payload
    echo -ne "$input" > "$output"
    # Use Python to calculate and append CRC
    python3 -c "
import sys
data = open('$output', 'rb').read()
def crc16(buf):
    crc = 0xFFFF
    for b in buf:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc
crc = crc16(data)
with open('$output', 'ab') as f:
    f.write(bytes([crc & 0xFF, (crc >> 8) & 0xFF]))
"
}

# RTU FC 0x01: Read coils (slave=1, fc=1, addr=0x0130, qty=37)
append_crc '\x01\x01\x01\x30\x00\x25' "$SEEDS_DIR/rtu/fc01_read_coils.raw"

# RTU FC 0x03: Read holding registers
append_crc '\x01\x03\x00\x00\x00\x0a' "$SEEDS_DIR/rtu/fc03_read_holding.raw"

# RTU FC 0x05: Write single coil ON
append_crc '\x01\x05\x01\x30\xff\x00' "$SEEDS_DIR/rtu/fc05_write_coil_on.raw"

# RTU FC 0x06: Write single register
append_crc '\x01\x06\x01\x60\x12\x34' "$SEEDS_DIR/rtu/fc06_write_register.raw"

# RTU Broadcast (slave=0)
append_crc '\x00\x06\x01\x60\x12\x34' "$SEEDS_DIR/rtu/broadcast_write.raw"

# RTU FC 0x10: Write multiple registers
append_crc '\x01\x10\x01\x60\x00\x02\x04\x00\x0a\x01\x02' "$SEEDS_DIR/rtu/fc10_write_registers.raw"

echo "Creating ZIP archives..."

# Create ZIP archives for each fuzzer
cd "$SEEDS_DIR"
zip -j FuzzServer_seed_corpus.zip server/*.raw
zip -j FuzzClient_seed_corpus.zip client/*.raw
zip -j FuzzClientWrite_seed_corpus.zip client/*.raw  # Same responses work for client write
zip -j FuzzClientRead_seed_corpus.zip clientread/*.raw
zip -j FuzzServerRTU_seed_corpus.zip rtu/*.raw
zip -j FuzzDataConversion_seed_corpus.zip dataconv/*.raw

# Move to parent directory
mv *.zip ..

echo "Seed corpus generation complete!"
echo "Created files:"
ls -la "$SCRIPT_DIR"/*.zip
