#pragma once

#ifndef SCRYPT_H
#define SCRYPT_H

void scrypt(
    const unsigned char* P, size_t p_len, 
    const unsigned char* S, size_t s_len, 
    int N, int r, int p, 
    unsigned char* out, size_t out_len);

#endif