#pragma once

#ifndef PBKDF2_H
#define PBKDF2_H

#include <stdint.h>

// transform int to char in big-endian
void int_to_bytes(uint32_t i, uint8_t* out);

// functional func? with main logic
void pbkdf2_hmac_sha256_F(const uint8_t* P, uint32_t plen, const uint8_t* S, uint32_t slen, uint32_t c, uint32_t i, uint8_t* out, uint32_t hlen);

// pbkdf2-hmac-sha256 crypto func
void pbkdf2_hmac_sha256(const uint8_t* P, int plen, const uint8_t* S, int slen, uint32_t c, uint32_t dkLen, uint8_t* DK);

#endif