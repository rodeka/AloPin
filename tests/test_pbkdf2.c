#include <check.h>
#include "crypto/pbkdf2.h"

START_TEST(test_pbkdf2_same_as_OpenSSL){
    const char password[] = {'1', '2', '3', '4'};
    const char salt[] = {0x29, 0xBE, 0xC0, 0xE9, 0x3E, 0x91, 0xAB, 0xB0};
    uint32_t iters = 10000;
    uint8_t dk1[32];
    uint8_t dk2[32] = {
        0xa2, 0x4f, 0x71, 0x8f, 0x47, 0x44, 0x97, 0x98,
        0x4f, 0x78, 0x68, 0xcc, 0xf4, 0x00, 0x53, 0x56,
        0xb3, 0x81, 0x1a, 0x41, 0x18, 0x3a, 0x49, 0x79,
        0xac, 0xab, 0xe3, 0x15, 0x40, 0x90, 0x96, 0x07};

    pbkdf2_hmac_sha256((const unsigned char*)password, sizeof(password), (const unsigned char*)salt, sizeof(salt), iters, dk1, sizeof(dk1));

    ck_assert_mem_eq(dk1, dk2, sizeof(dk1));
}
END_TEST


START_TEST(test_pbkdf2_same_behaviour){
    const char password[] = {'1', '2', '3', '4'};
    const char salt[] = {0x29, 0xBE, 0xC0, 0xE9, 0x3E, 0x91, 0xAB, 0xB0};
    uint32_t iters = 10000;
    uint8_t dk1[32];
    uint8_t dk2[32];

    pbkdf2_hmac_sha256((const unsigned char*)password, sizeof(password), (const unsigned char*)salt, sizeof(salt), iters, dk1, sizeof(dk1));

    pbkdf2_hmac_sha256((const unsigned char*)password, sizeof(password), (const unsigned char*)salt, sizeof(salt), iters, dk2, sizeof(dk2));

    ck_assert_mem_eq(dk1, dk2, sizeof(dk1));
}

Suite* pbkdf2_suite(){
    Suite* s = suite_create("PBKDF2");

    TCase* tc_pbkdf2_same_as_OpenSSL = tcase_create("PBKDF2_same_as_in_OpenSSL");
    tcase_add_test(tc_pbkdf2_same_as_OpenSSL, test_pbkdf2_same_as_OpenSSL);
    suite_add_tcase(s, tc_pbkdf2_same_as_OpenSSL);

    TCase* tc_pbkdf2_same_behaviour = tcase_create("PBKDF2_same_behavior");
    tcase_add_test(tc_pbkdf2_same_behaviour, test_pbkdf2_same_behaviour);
    suite_add_tcase(s, tc_pbkdf2_same_behaviour);
    return s;
}

int main(){
    int fail_count;
    Suite* s = pbkdf2_suite();
    SRunner* sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    fail_count = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (fail_count == 0) ? 0 : 1;
}