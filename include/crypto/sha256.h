// this header have no sha256_ctx/init/update/final
// 'cause it's cut verison of real sha256 and it's optimaze 
// only for this prog.
#pragma once

#ifndef SHA256_H
#define SHA256_H

#define SHA256_DIGEST_LENGTH 32
#define SHA256_BLOCK_SIZE 64

void sha256(const unsigned char* data, int data_len, 
            unsigned char* out_hash);

#endif