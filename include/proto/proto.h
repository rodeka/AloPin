#pragma once

#ifndef PROTO_H
#define PROTO_H

int proto_extract_field_raw(const unsigned char* buf, size_t buf_len, int field_number, unsigned char** out_data, size_t* out_len);

#endif // PROTO_H