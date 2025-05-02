#include <check.h>

#include "crypto/scrypt.h"

START_TEST(test_scrypt_check_behaviour){
    const unsigned char password[] = {'1', '2', '3', '4'};
    const unsigned char salt[] = {0x29, 0xBE, 0xC0, 0xE9, 0x3E, 0x91, 0xAB, 0xB0};
    uint32_t N = 8192;
    uint32_t r = 8;
    uint32_t p = 1;
    uint8_t dk1[32];
    uint8_t dk2[32] = {
        0xfc, 0xa6, 0xfc, 0x47, 0x93, 0xd2, 0x71, 0x11,
        0x4f, 0xd6, 0x33, 0xed, 0x0f, 0x9a, 0xb1, 0xb1,
        0x3a, 0xd7, 0x1c, 0xc5, 0x3e, 0x60, 0x73, 0xc2,
        0x6d, 0x31, 0x7d, 0xe7, 0x08, 0xe2, 0xa5, 0x58
    };

    scrypt((const unsigned char*)password, sizeof(password), (const unsigned char*)salt, sizeof(salt), N, r, p, dk1, sizeof(dk1));

    ck_assert_mem_eq(dk1, dk2, sizeof(dk1));
}


START_TEST(test_scrypt_same_behaviour){
    const unsigned char password[] = {'1', '2', '3', '4'};
    const unsigned char salt[] = {0x29, 0xBE, 0xC0, 0xE9, 0x3E, 0x91, 0xAB, 0xB0};
    uint32_t N = 16384;
    uint32_t r = 8;
    uint32_t p = 1;
    uint8_t dk1[32];
    uint8_t dk2[32];

    scrypt((const unsigned char*)password, sizeof(password), (const unsigned char*)salt, sizeof(salt), N, r, p, dk1, sizeof(dk1));

    scrypt((const unsigned char*)password, sizeof(password), (const unsigned char*)salt, sizeof(salt), N, r, p, dk2, sizeof(dk2));

    ck_assert_mem_eq(dk1, dk2, sizeof(dk1));
}

Suite* scrypt_suite(){
    Suite* s = suite_create("SCRYPT");
    
    TCase* tc_scrypt_check_behaviour = tcase_create("SCRYPT_check_behaviour");
    tcase_add_test(tc_scrypt_check_behaviour, test_scrypt_check_behaviour);
    suite_add_tcase(s, tc_scrypt_check_behaviour);

    TCase* tc_scrypt_same_behaviour = tcase_create("SCRYPT_same_behavior");
    tcase_add_test(tc_scrypt_same_behaviour, test_scrypt_same_behaviour);
    suite_add_tcase(s, tc_scrypt_same_behaviour);
    
    return s;
}

int main(){
    int fail_count;
    Suite* s = scrypt_suite();
    SRunner* sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    fail_count = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (fail_count == 0) ? 0 : 1;
}