#pragma once

#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include <stdint.h>
#include "crypto/sha256.h"

void hmac_sha256(const unsigned char* key, size_t key_len,
                 const unsigned char* msg, size_t msg_len,
                 unsigned char* mac);

#endif