#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include "sha256.h"

#define HMAC_SHA256_LENGTH 32 // Độ dài đầu ra HMAC-SHA256 (32 byte)

/**
 * Tính HMAC-SHA256 cho dữ liệu với khóa cho trước.
 * @param key Con trỏ đến khóa bí mật.
 * @param key_len Độ dài khóa (byte).
 * @param data Con trỏ đến dữ liệu cần tính HMAC.
 * @param data_len Độ dài dữ liệu (byte).
 * @param hmac_output Mảng 32 byte để lưu kết quả HMAC.
 */
void hmac_sha256(const BYTE *key, size_t key_len, const BYTE *data, size_t data_len, BYTE *hmac_output);

#endif // HMAC_SHA256_H