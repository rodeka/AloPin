#pragma once

#ifndef PROTO_H
#define PROTO_H
#include <stdint.h>

static int read_varint(const uint8_t* buf, uint32_t buf_len, uint32_t* offset, uint64_t* value, uint32_t* varint_len);

static int skip_field(const uint8_t* buf, uint32_t buf_len, uint32_t* offset, uint32_t wire_type);

int extract_field_raw(const uint8_t *buf, uint32_t buf_len, uint32_t field_number, uint8_t **out_data, uint32_t *out_len);

#endif // PROTO_H