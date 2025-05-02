#pragma once

#ifndef PROTO_H
#define PROTO_H
#include <stdint.h>

int proto_extract_field_raw(const uint8_t *buf, uint32_t buf_len, uint32_t field_number, uint8_t **out_data, uint32_t *out_len);

#endif // PROTO_H