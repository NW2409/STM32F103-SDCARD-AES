#ifndef PBKDF2_H
#define PBKDF2_H

#include <stdint.h>
#include "sha256.h"

void pbkdf2_sha256(const uint8_t *password, uint32_t password_len,
                   const uint8_t *salt, uint32_t salt_len,
                   uint32_t iterations, uint8_t *key, uint32_t key_len);

#endif