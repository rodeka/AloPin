#include "crypto/hmac_sha256.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t* mac)
{
    uint8_t k0[SHA256_BLOCK_SIZE];
    uint8_t ipad[SHA256_BLOCK_SIZE];
    uint8_t opad[SHA256_BLOCK_SIZE];
    
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256(key, key_len, k0);
        key_len = 32;
        memset(k0 + 32, 0, SHA256_BLOCK_SIZE - 32);
    } else {
        memcpy(k0, key, key_len);
        memset(k0 + key_len, 0, SHA256_BLOCK_SIZE - key_len);
    }

    for (int i = 0; i < SHA256_BLOCK_SIZE; ++i) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }

    uint8_t* inner_buf = malloc(SHA256_BLOCK_SIZE + msg_len);
    uint8_t* inner_hash[SHA256_DIGEST_LENGTH];
    memcpy(inner_buf, ipad, SHA256_BLOCK_SIZE);
    memcpy(inner_buf + SHA256_BLOCK_SIZE, msg,  msg_len);
    sha256(inner_buf, SHA256_BLOCK_SIZE + msg_len, (unsigned char*)inner_hash);
    free(inner_buf);

    uint8_t outer_buf[SHA256_BLOCK_SIZE + SHA256_DIGEST_LENGTH];
    memcpy(outer_buf, opad, SHA256_BLOCK_SIZE);
    memcpy(outer_buf + SHA256_BLOCK_SIZE, inner_hash, SHA256_DIGEST_LENGTH);
    sha256(outer_buf, SHA256_BLOCK_SIZE + SHA256_DIGEST_LENGTH, mac);
}
