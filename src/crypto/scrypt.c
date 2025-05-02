#include "crypto/scrypt.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define R 8

static inline uint32_t ROTL32(uint32_t v, unsigned c) {
    return (v << c) | (v >> (32 - c));
}

static void uint32_to_le(uint32_t v, uint8_t *p){
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline uint32_t le_to_uint32(const uint8_t *p){
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void salsa20_8(uint8_t* out, const uint8_t* in){
    uint32_t x[16], orig[16];

    for (int i = 0; i < 16; i++)
        orig[i] = x[i] = le_to_uint32(in + 4 * i);

    for (int i = 0; i < 8; i += 2) {
        // column round
        x[ 4] ^= ROTL32(x[ 0] + x[12], 7);
        x[ 8] ^= ROTL32(x[ 4] + x[ 0], 9);
        x[12] ^= ROTL32(x[ 8] + x[ 4],13);
        x[ 0] ^= ROTL32(x[12] + x[ 8],18);

        x[ 9] ^= ROTL32(x[ 5] + x[ 1], 7);
        x[13] ^= ROTL32(x[ 9] + x[ 5], 9);
        x[ 1] ^= ROTL32(x[13] + x[ 9],13);
        x[ 5] ^= ROTL32(x[ 1] + x[13],18);

        x[14] ^= ROTL32(x[10] + x[ 6], 7);
        x[ 2] ^= ROTL32(x[14] + x[10], 9);
        x[ 6] ^= ROTL32(x[ 2] + x[14],13);
        x[10] ^= ROTL32(x[ 6] + x[ 2],18);

        x[ 3] ^= ROTL32(x[15] + x[11], 7);
        x[ 7] ^= ROTL32(x[ 3] + x[15], 9);
        x[11] ^= ROTL32(x[ 7] + x[ 3],13);
        x[15] ^= ROTL32(x[11] + x[ 7],18);

        // row round
        x[ 1] ^= ROTL32(x[ 0] + x[ 3], 7);
        x[ 2] ^= ROTL32(x[ 1] + x[ 0], 9);
        x[ 3] ^= ROTL32(x[ 2] + x[ 1],13);
        x[ 0] ^= ROTL32(x[ 3] + x[ 2],18);

        x[ 6] ^= ROTL32(x[ 5] + x[ 4], 7);
        x[ 7] ^= ROTL32(x[ 6] + x[ 5], 9);
        x[ 4] ^= ROTL32(x[ 7] + x[ 6],13);
        x[ 5] ^= ROTL32(x[ 4] + x[ 7],18);

        x[11] ^= ROTL32(x[10] + x[ 9], 7);
        x[ 8] ^= ROTL32(x[11] + x[10], 9);
        x[ 9] ^= ROTL32(x[ 8] + x[11],13);
        x[10] ^= ROTL32(x[ 9] + x[ 8],18);

        x[12] ^= ROTL32(x[15] + x[14], 7);
        x[13] ^= ROTL32(x[12] + x[15], 9);
        x[14] ^= ROTL32(x[13] + x[12],13);
        x[15] ^= ROTL32(x[14] + x[13],18);
    }

    for (int i = 0; i < 16; i++)
        x[i] += orig[i];

    for (int i = 0; i < 16; i++)
        uint32_to_le(x[i], out + 4 * i);
}


static void BlockMix(uint8_t* out, const uint8_t* in){
    uint8_t X[64];
    memcpy(X, in + (2 * R - 1) * 64, 64);

    for (int i = 0; i < 2 * R; i++) {
        for (int j = 0; j < 64; j++)
            X[j] ^= in[i * 64 + j];

        salsa20_8(X, X);

        if ((i & 1) == 0)
            memcpy(out + (i / 2) * 64, X, 64);
        else
            memcpy(out + (R + i / 2) * 64, X, 64);
    }
}

static inline uint64_t integerify(const uint8_t* X){
    const uint8_t *last64 = X + (128 * R - 64);
    return (uint64_t)le_to_uint32(last64) | ((uint64_t)le_to_uint32(last64 + 4) << 32);
}

static void ROMix(uint8_t* B, uint32_t N){
    const size_t blk = 128 * R;
    uint8_t *V = malloc((size_t)N * blk);
    uint8_t *X = malloc(blk);
    uint8_t *Y = malloc(blk);

    memcpy(X, B, blk);

    for (uint32_t i = 0; i < N; i++) {
        memcpy(V + (size_t)i * blk, X, blk);
        BlockMix(Y, X);
        memcpy(X, Y, blk);
    }

    for (uint32_t i = 0; i < N; i++) {
        uint64_t j = integerify(X) & (N - 1);
        uint8_t *Vj = V + j * blk;

        for (size_t k = 0; k < blk; k++)
            X[k] ^= Vj[k];

        BlockMix(Y, X);
        memcpy(X, Y, blk);
    }

    memcpy(B, X, blk);

    free(Y);
    free(X);
    free(V);
}


void scrypt(const unsigned char* P, size_t p_len, const unsigned char* S, size_t s_len, int N, int r, int p, unsigned char* out, size_t out_len){
    const size_t B_len = (size_t)p * 128 * r;
    uint8_t* B = (uint8_t*)malloc(B_len);

    pbkdf2_hmac_sha256(P, p_len, S, s_len, 1, B, B_len);

    for (uint32_t i = 0; i < p; i++)
        ROMix(B + (size_t)i * 128 * r, N);

    pbkdf2_hmac_sha256(P, p_len, B, B_len, 1, out, out_len);

    free(B);
}