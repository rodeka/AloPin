#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "crypto/pbkdf2.h"
#include "crypto/hmac_sha256.h"


static void int_to_bytes(uint32_t i, uint8_t* out){
    for(int j = 0; j < 4; j++){
        out[j] = (i >> (24 - 8 * j)) & 0xFF;
    }
}


int _pbkdf2_hmac_sha256_F(const uint8_t* P, uint32_t p_len, const uint8_t* S, uint32_t s_len, uint32_t c, uint32_t i, uint8_t* out, uint32_t hlen){
    uint8_t* salt_block = malloc(s_len + 4);
    if(!salt_block){
        fprintf(stderr, "Error pbkdf2: cannot allocate salt_block\n");
        return -1;
    }

    memcpy(salt_block, S, s_len);
    int_to_bytes(i, salt_block + s_len);

    uint8_t* U_prev = malloc(hlen);
    if(!U_prev){
        fprintf(stderr, "Error pbkdf2: cannot allocate U_prev\n");
        free(salt_block);
        return -1;
    }

    uint8_t* U_result = malloc(hlen);
    if(!U_result){
        fprintf(stderr, "Error pbkdf2: cannot allocate U_result\n");
        free(U_prev);
        free(salt_block);
        return -1;
    }

    hmac_sha256(P, p_len, salt_block, s_len + 4, U_prev);
    free(salt_block);
    memcpy(U_result, U_prev, hlen);

    for(uint32_t j = 2; j <= c; j++){
        hmac_sha256(P, p_len, U_prev, hlen, U_prev);

        for(uint32_t k = 0; k < hlen; k++){
            U_result[k] ^= U_prev[k];
        }
    }

    memcpy(out, U_result, hlen);
    free(U_prev);
    free(U_result);
}


int pbkdf2_hmac_sha256(const unsigned char* P, size_t p_len, const unsigned char* S, size_t s_len, int iters, unsigned char* DK, size_t dk_len){
    const uint32_t hlen = SHA256_DIGEST_LENGTH;

    if(dk_len > (0xFFFFFFFF - 1) * hlen){
        fprintf(stderr, "Error pbkdf2: dk_len too big.\n");
        return -1;
    }

    uint32_t l = (dk_len + hlen - 1) / hlen;
    uint32_t r = dk_len - (l - 1) * hlen;

    uint8_t block[SHA256_DIGEST_LENGTH];
    for(uint32_t i = 1; i < l; i++){
        _pbkdf2_hmac_sha256_F(P, p_len, S, s_len, iters, i, block, hlen);
        memcpy(DK + (i - 1) * hlen, block, hlen);
    }
    _pbkdf2_hmac_sha256_F(P, p_len, S, s_len, iters, l, block, hlen);
    memcpy(DK + (l - 1) * hlen, block, r);
}