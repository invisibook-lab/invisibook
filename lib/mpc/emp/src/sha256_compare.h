#ifndef SHA256_COMPARE_H
#define SHA256_COMPARE_H

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <emp-tool/emp-tool.h>
#include <emp-ag2pc/emp-ag2pc.h>

/**
 * SHA-256 Commitment Verification + Comparison via emp-ag2pc.
 *
 * Both parties input both commitments C1 and C2 for malicious security.
 * The circuit verifies commitment consistency before checking hashes.
 *
 * Circuit input layout (big-endian bit encoding):
 *   Alice (1024 bits): padded_msg1[512] || C1[256] || C2[256]
 *   Bob   (1024 bits): padded_msg2[512] || C1[256] || C2[256]
 *
 *   padded_msg = v[64] || r[256] || 1 || 0*127 || 0x0000000000000140[64]
 *
 * Circuit output (2 bits):
 *   output[0] = valid (consistency + commitment checks all passed)
 *   output[1] = v1 > v2 (unsigned 64-bit comparison)
 */

// Number of input bits per party
static const int PARTY_INPUT_BITS = 1024;

/**
 * Convert a uint64 to big-endian bits (MSB first).
 */
inline void u64_to_bits_be(uint64_t val, bool* bits, int nbits) {
    for (int i = 0; i < nbits; i++) {
        bits[i] = (val >> (nbits - 1 - i)) & 1;
    }
}

/**
 * Convert a byte array to big-endian bits.
 * Each byte is expanded MSB-first: byte[0] bit7, byte[0] bit6, ..., byte[0] bit0, byte[1] bit7, ...
 */
inline void bytes_to_bits_be(const uint8_t* data, int len, bool* bits) {
    for (int i = 0; i < len; i++) {
        for (int b = 7; b >= 0; b--) {
            bits[i * 8 + (7 - b)] = (data[i] >> b) & 1;
        }
    }
}

/**
 * Parse a hex string into a byte array.
 * Returns number of bytes parsed. hex must have even length.
 */
inline int hex_to_bytes(const char* hex, uint8_t* out, int max_len) {
    int hex_len = strlen(hex);
    int byte_len = hex_len / 2;
    if (byte_len > max_len) byte_len = max_len;
    for (int i = 0; i < byte_len; i++) {
        unsigned int byte_val;
        sscanf(hex + 2 * i, "%02x", &byte_val);
        out[i] = (uint8_t)byte_val;
    }
    return byte_len;
}

/**
 * Prepare SHA-256 padded message from value (64-bit) and randomness (256-bit).
 *
 * Message layout (320 bits = 40 bytes):
 *   v[64] || r[256]
 *
 * SHA-256 padding for 320-bit (40-byte) message:
 *   msg[320] || 1 || 0*127 || length[64]
 *   = 320 + 1 + 127 + 64 = 512 bits
 *
 * length = 320 = 0x0140
 *
 * Output: 512 bits in big-endian order.
 */
inline void sha256_pad_message(uint64_t v, const uint8_t r[32], bool* padded_512) {
    memset(padded_512, 0, 512 * sizeof(bool));

    // v as 64 big-endian bits (bits 0..63)
    u64_to_bits_be(v, &padded_512[0], 64);

    // r as 256 big-endian bits (bits 64..319)
    bytes_to_bits_be(r, 32, &padded_512[64]);

    // Padding bit (bit 320)
    padded_512[320] = true;

    // Zero padding (bits 321..447) — already zeroed

    // Length field: 320 = 0x0000000000000140 as 64-bit big-endian (bits 448..511)
    uint64_t msg_len_bits = 320;
    u64_to_bits_be(msg_len_bits, &padded_512[448], 64);
}

struct CompareResult {
    bool valid;       // commitment verification passed
    bool v1_greater;  // v1 > v2
};

/**
 * Run the SHA-256 commitment comparison 2PC protocol.
 *
 * Each party provides their own secret (v, r) and BOTH public commitments (C1, C2).
 * The circuit verifies that both parties agree on the commitments before checking.
 *
 * @param party        ALICE (1) or BOB (2)
 * @param io           Network connection
 * @param my_v         My secret value (uint64)
 * @param my_r         My secret randomness (32 bytes)
 * @param C1           Commitment 1 = SHA-256(v1 || r1) (32 bytes, known to both)
 * @param C2           Commitment 2 = SHA-256(v2 || r2) (32 bytes, known to both)
 * @param circuit_file Path to the composed Bristol circuit
 * @return CompareResult with valid and v1_greater fields
 */
inline CompareResult run_sha256_compare(
    int party,
    emp::NetIO* io,
    uint64_t my_v,
    const uint8_t my_r[32],
    const uint8_t C1[32],
    const uint8_t C2[32],
    const char* circuit_file
) {
    using namespace emp;

    BristolFormat cf(circuit_file);

    // Prepare 1024-bit input: padded_msg[512] || C1[256] || C2[256]
    bool input[PARTY_INPUT_BITS];
    memset(input, false, sizeof(input));

    // [0..511] = SHA-256 padded message (v || r || padding)
    sha256_pad_message(my_v, my_r, &input[0]);

    // [512..767] = C1
    bytes_to_bits_be(C1, 32, &input[512]);

    // [768..1023] = C2
    bytes_to_bits_be(C2, 32, &input[768]);

    // Run 2PC protocol
    C2PC<NetIO> twopc(io, party, &cf);
    twopc.function_independent();
    twopc.function_dependent();

    bool output[2] = {false, false};
    twopc.online(input, output);

    CompareResult result;
    result.valid = output[0];
    result.v1_greater = output[1];
    return result;
}

#endif // SHA256_COMPARE_H
