#include "hmac_sha256.h"
#include <string.h>

/**
 * Tính HMAC-SHA256 theo chu?n RFC 2104.
 * Công th?c: HMAC(K, m) = SHA256((K' ? opad) || SHA256((K' ? ipad) || m))
 */
void hmac_sha256(const BYTE *key, size_t key_len, const BYTE *data, size_t data_len, BYTE *hmac_output) {
    BYTE key_padded[64]; // Kh?i SHA256 là 64 byte
    BYTE temp[64];
    BYTE inner_hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;

    // Bu?c 1: Chu?n b? khóa
    if (key_len > 64) {
        // N?u khóa dài hon 64 byte, bam b?ng SHA256
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, key_padded);
        memset(key_padded + SHA256_BLOCK_SIZE, 0, 64 - SHA256_BLOCK_SIZE); // Ð?m 0
    } else {
        // N?u khóa ng?n hon ho?c b?ng 64 byte, sao chép và d?m 0
        memcpy(key_padded, key, key_len);
        memset(key_padded + key_len, 0, 64 - key_len);
    }

    // Bu?c 2: Tính inner hash: SHA256((key ? ipad) || data)
    for (int i = 0; i < 64; i++) {
        temp[i] = key_padded[i] ^ 0x36; // ipad = 0x36 l?p l?i
    }
    sha256_init(&ctx);
    sha256_update(&ctx, temp, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner_hash);

    // Bu?c 3: Tính outer hash: SHA256((key ? opad) || inner_hash)
    for (int i = 0; i < 64; i++) {
        temp[i] = key_padded[i] ^ 0x5C; // opad = 0x5C l?p l?i
    }
    sha256_init(&ctx);
    sha256_update(&ctx, temp, 64);
    sha256_update(&ctx, inner_hash, SHA256_BLOCK_SIZE);
    sha256_final(&ctx, hmac_output);
}