#pragma once

#ifndef SCRYPT_H
#define SCRYPT_H

#include <stdint.h>

void uint32_to_le(uint32_t v, uint8_t* p);

void salsa20_8(uint8_t* out, const uint8_t* in);

void BlockMix(uint8_t* out, const uint8_t* in);

void ROMix(uint8_t* B, uint32_t N);

void scrypt(const uint8_t* P, uint32_t plen, const uint8_t* S, uint32_t slen, uint32_t N, uint32_t r, uint32_t p, uint8_t* out, uint32_t dkLen);

#endif