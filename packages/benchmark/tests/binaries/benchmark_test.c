/**
 * benchmark_test.c — Small test binary for AETHER benchmarking.
 *
 * Compile (Windows with MSVC):
 *   cl /O2 /GS- benchmark_test.c /link /SUBSYSTEM:CONSOLE /OUT:benchmark_test.exe
 *
 * Compile (Linux/Mac with GCC/Clang):
 *   gcc -O2 -o benchmark_test benchmark_test.c
 *
 * This binary has 4 small but distinct functions that AETHER should annotate:
 *   1. xor_encrypt     — XOR-based buffer encryption
 *   2. hex_encode      — Binary-to-hex string conversion
 *   3. validate_crc8   — Simple CRC-8 checksum validation
 *   4. str_append      — Safe string concatenation with length check
 *   5. main            — Entry point that calls the above
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── 1. XOR encryption ──────────────────────────────────────────────── */

void xor_encrypt(uint8_t *buffer, size_t len, uint8_t key) {
    for (size_t i = 0; i < len; i++) {
        buffer[i] ^= key;
    }
}

/* ── 2. Binary-to-hex encoding ──────────────────────────────────────── */

void hex_encode(const uint8_t *input, size_t input_len, char *output) {
    const char *hex_chars = "0123456789ABCDEF";
    for (size_t i = 0; i < input_len; i++) {
        output[i * 2]     = hex_chars[(input[i] >> 4) & 0x0F];
        output[i * 2 + 1] = hex_chars[input[i] & 0x0F];
    }
    output[input_len * 2] = '\0';
}

/* ── 3. CRC-8 validation ────────────────────────────────────────────── */

#define CRC8_POLY 0x07

uint8_t compute_crc8(const uint8_t *data, size_t len) {
    uint8_t crc = 0x00;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 0x80)
                crc = (uint8_t)((crc << 1) ^ CRC8_POLY);
            else
                crc <<= 1;
        }
    }
    return crc;
}

int validate_crc8(const uint8_t *data, size_t len, uint8_t expected) {
    return compute_crc8(data, len) == expected;
}

/* ── 4. Safe string append ──────────────────────────────────────────── */

size_t str_append(char *dst, size_t dst_cap, const char *src) {
    size_t dst_len = strlen(dst);
    size_t src_len = strlen(src);
    size_t space   = dst_cap - dst_len - 1;

    if (space == 0)
        return dst_len;  /* no room */

    size_t to_copy = src_len < space ? src_len : space;
    memcpy(dst + dst_len, src, to_copy);
    dst[dst_len + to_copy] = '\0';
    return dst_len + to_copy;
}

/* ── 5. Main ────────────────────────────────────────────────────────── */

int main(void) {
    uint8_t  secret[]  = "HelloAETHER";
    size_t   secret_len = strlen((const char *)secret);
    char     hex_buf[256];
    uint8_t  key = 0xAB;

    printf("Original: %s\n", secret);

    /* Encrypt */
    xor_encrypt(secret, secret_len, key);
    hex_encode(secret, secret_len, hex_buf);
    printf("Encrypted (hex): %s\n", hex_buf);

    /* Decrypt */
    xor_encrypt(secret, secret_len, key);
    hex_encode(secret, secret_len, hex_buf);
    printf("Decrypted (hex): %s\n", hex_buf);

    /* CRC-8 */
    uint8_t crc = compute_crc8((const uint8_t *)"AETHER", 6);
    printf("CRC-8 of 'AETHER': 0x%02X\n", crc);

    /* String append */
    char buf[32] = "AETHER";
    str_append(buf, sizeof(buf), "_benchmark");
    printf("Appended: %s\n", buf);

    return 0;
}
