#include "pbkdf2.h"
#include <string.h>

// Hàm HMAC-SHA256
static void hmac_sha256(const uint8_t *key, uint32_t key_len,
                        const uint8_t *data, uint32_t data_len,
                        uint8_t *out) {
    SHA256_CTX ctx;
    uint8_t k_ipad[64] = {0};
    uint8_t k_opad[64] = {0};
    uint8_t temp[32];

    // Chuẩn bị khóa: Nếu khóa dài hơn 64 byte, băm nó xuống 32 byte
    if (key_len > 64) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, k_ipad);
        memcpy(k_opad, k_ipad, 32);
    } else {
        memcpy(k_ipad, key, key_len);
        memcpy(k_opad, key, key_len);
    }

    // XOR với ipad (0x36) và opad (0x5c)
    for (int i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    // Inner hash: SHA256(k_ipad || data)
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, temp);

    // Outer hash: SHA256(k_opad || inner_hash)
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, temp, 32);
    sha256_final(&ctx, out);
}

void pbkdf2_sha256(const uint8_t *password, uint32_t password_len,
                   const uint8_t *salt, uint32_t salt_len,
                   uint32_t iterations, uint8_t *key, uint32_t key_len) {
    uint8_t block[32];
    uint8_t temp[32];
    uint32_t block_num = 1;
    uint32_t key_pos = 0;

    while (key_pos < key_len) {
        // Chuẩn bị dữ liệu: salt || block_number (big-endian)
        uint8_t data[64];
        memcpy(data, salt, salt_len);
        data[salt_len] = (block_num >> 24) & 0xFF;
        data[salt_len + 1] = (block_num >> 16) & 0xFF;
        data[salt_len + 2] = (block_num >> 8) & 0xFF;
        data[salt_len + 3] = block_num & 0xFF;

        // F = HMAC(password, salt || block_number)
        hmac_sha256(password, password_len, data, salt_len + 4, block);
        memcpy(temp, block, 32);

        // Lặp iterations - 1 lần
        for (uint32_t i = 1; i < iterations; i++) {
            hmac_sha256(password, password_len, temp, 32, temp);
            for (int j = 0; j < 32; j++) {
                block[j] ^= temp[j];
            }
        }

        // Sao chép kết quả vào key
        uint32_t bytes_to_copy = (key_len - key_pos > 32) ? 32 : (key_len - key_pos);
        memcpy(key + key_pos, block, bytes_to_copy);
        key_pos += bytes_to_copy;
        block_num++;
    }
}