#pragma once

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h> 

#define SHA256_DIGEST_LENGTH 32
#define SHA256_BLOCK_SIZE 64

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint32_t bitlen[2];
    uint32_t state[8];
} SHA256_CTX;

void _sha256Init(SHA256_CTX *ctx);
void _sha256Update(SHA256_CTX *ctx, const int8_t* data, uint32_t len);
void _sha256Final(SHA256_CTX *ctx, uint8_t* hash);

void sha256(const unsigned char* data, int data_len, 
            unsigned char* out_hash);

#endif