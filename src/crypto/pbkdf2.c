#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "pbkdf2.h"


void int_to_bytes(uint32_t i, uint8_t* out){
    for(int j = 0; j < 4; j++){
        out[j] = (i >> (24 - 8 * j)) & 0xFF;
    }
}


void pbkdf2_hmac_sha256_F(const uint8_t* P, uint32_t plen, const uint8_t* S, uint32_t slen, uint32_t c, uint32_t i, uint8_t* out, uint32_t hlen){
    uint8_t salt_block[slen + 4];
    memcpy(salt_block, S, slen);
    int_to_bytes(i, salt_block + slen);

    uint8_t U_prev[hlen];
    uint8_t U_result[hlen];

    HMAC(EVP_sha256(), P, plen, salt_block, slen + 4, U_prev, NULL);
    memcpy(U_result, U_prev, hlen);

    for(uint32_t j = 2; j <= c; j++){
        HMAC(EVP_sha256(), P, plen, U_prev, hlen, U_prev, NULL);

        for(uint32_t k = 0; k < hlen; k++){
            U_result[k] ^= U_prev[k];
        }
    }

    memcpy(out, U_result, hlen);
}


void pbkdf2_hmac_sha256(const uint8_t* P, int plen, const uint8_t* S, int slen, uint32_t c, uint32_t dkLen, uint8_t* DK){
    const uint32_t hlen = SHA256_DIGEST_LENGTH;

    if(dkLen > (0xFFFFFFFF - 1) * hlen){
        fprintf(stderr, "Error: dkLen too big.\n");
        exit(1);
    }

    uint32_t l = (dkLen + hlen - 1) / hlen;
    uint32_t r = dkLen - (l - 1) * hlen;

    for(uint32_t i = 1; i <= l; i++){
        uint8_t block[hlen];
        pbkdf2_hmac_sha256_F(P, plen, S, slen, c, i, block, hlen);

        if(i == l){
            memcpy(DK + (i - 1) * hlen, block, r);
        }
        else{
            memcpy(DK + (i - 1) * hlen, block, hlen);
        }
    }
}