#include <proto/proto.h>
#include <stdlib.h>

static int read_varint(const uint8_t* buf, uint32_t buf_len, uint32_t* offset, uint64_t* value, uint32_t* varint_len){
    uint64_t v = 0;
    uint32_t shift = 0;
    uint32_t i = *offset;
    *varint_len = 0;

    while (i < buf_len && *varint_len < 10) {
        uint8_t byte = buf[i++];
        v |= (uint64_t)(byte & 0x7F) << shift;
        (*varint_len)++;
        if((byte & 0x80) == 0){
            *value = v;
            *offset = i;
            return 0;
        }
        shift += 7;
    }
        return -1;
}


static int skip_field(const uint8_t* buf, uint32_t buf_len, uint32_t* offset, uint32_t wire_type){
    switch(wire_type){
        case 0:// varint
            uint64_t tmp;
            uint32_t len;
            return read_varint(buf, buf_len, offset, &tmp, &len);
        case 1: // fixed64
            if (*offset + 8 > buf_len)
                return -1;
            *offset += 8;
            return 0;
        case 2: { // length-delimited
            uint64_t length;
            uint32_t len_len;
            if(read_varint(buf, buf_len, offset, &length, &len_len) < 0)
                return -1;
            if(*offset + length > buf_len)
                return -1;
            *offset += length;
            return 0;
        }
        case 5: // fixed32
            if(*offset + 4 > buf_len) 
                return -1;
            *offset += 4;
            return 0;
        default: // 3,4 doesn't support
            return -1;
    }
}


int proto_extract_field_raw(const uint8_t *buf, uint32_t buf_len, uint32_t field_number, uint8_t **out_data, uint32_t *out_len){
    uint32_t offset = 0;
    while (offset < buf_len) {
        uint64_t key;
        uint32_t key_len;
        if (read_varint(buf, buf_len, &offset, &key, &key_len) < 0)
            return -1;
        uint32_t tag = (uint32_t)(key >> 3);
        uint32_t wire_type= (uint32_t)(key & 0x7);

        if(tag == field_number){
            // нашли нужное поле — в зависимости от wire_type читаем его
            uint32_t start = offset;
            uint32_t data_len = 0;

            switch (wire_type) {
                case 0: // varint
                    uint64_t val;
                    uint32_t vlen;
                    if(read_varint(buf, buf_len, &offset, &val, &vlen) < 0)
                        return -1;
                    data_len = vlen;
                    break;
                case 1: // fixed64
                    if(offset + 8 > buf_len)
                        return -1;
                    data_len = 8;
                    offset += 8;
                    break;
                case 2: // length-delimited
                    uint64_t length;
                    uint32_t llen;
                    if (read_varint(buf, buf_len, &offset, &length, &llen) < 0)
                        return -1;
                    start += llen;       // тело сразу после длины
                    if(offset + length - llen > buf_len)
                        return -1;
                    data_len = (uint32_t)length;
                    offset += length;
                    break;
                case 5: // fixed32
                    if(offset + 4 > buf_len)
                        return -1;
                    data_len = 4;
                    offset += 4;
                    break;
                default: // 3,4 doesn't support
                    return -1;
            }

            uint8_t* result = (uint8_t*)malloc(data_len);
            if(!result)
                return -1;
            memcpy(result, buf + start, data_len);
            *out_data = result;
            *out_len  = data_len;
            return 1;
        }
        else{
        if (skip_field(buf, buf_len, &offset, wire_type) < 0)
            return -1;
        }
    }
    return 0;
}