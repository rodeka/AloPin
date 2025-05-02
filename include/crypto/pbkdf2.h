#pragma once

#ifndef PBKDF2_H
#define PBKDF2_H

int pbkdf2_hmac_sha256(
    const unsigned char* P, size_t p_len,
    const unsigned char* S, size_t s_len, 
    int iters, 
    unsigned char* DK, size_t dk_len
);

#endif