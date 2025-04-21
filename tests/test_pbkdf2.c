#include <check.h>
#include <openssl/evp.h>
#include "pbkdf2.h"

START_TEST(test_pbkdf2_same_as_OpenSSL){
    const char password[] = {'1', '2', '3', '4'};
    const char salt[] = {0x29, 0xBE, 0xC0, 0xE9, 0x3E, 0x91, 0xAB, 0xB0};
    uint32_t iters = 10000;
    uint8_t dk1[32];
    uint8_t dk2[32];

    pbkdf2_hmac_sha256((const unsigned char*)password, sizeof(password), (const unsigned char*)salt, sizeof(salt), iters, sizeof(dk1), dk1);

    PKCS5_PBKDF2_HMAC((const char*)password, sizeof(password), (const unsigned char*)salt, sizeof(salt), iters, EVP_sha256(), sizeof(dk2), dk2);

    ck_assert_mem_eq(dk1, dk2, sizeof(dk1));
}
END_TEST


START_TEST(test_pbkdf2_same_behaviour){
    const char password[] = {'1', '2', '3', '4'};
    const char salt[] = {0x29, 0xBE, 0xC0, 0xE9, 0x3E, 0x91, 0xAB, 0xB0};
    uint32_t iters = 10000;
    uint8_t dk1[32];
    uint8_t dk2[32];

    pbkdf2_hmac_sha256((const unsigned char*)password, sizeof(password), (const unsigned char*)salt, sizeof(salt), iters, sizeof(dk1), dk1);

    pbkdf2_hmac_sha256((const unsigned char*)password, sizeof(password), (const unsigned char*)salt, sizeof(salt), iters, sizeof(dk2), dk2);

    ck_assert_mem_eq(dk1, dk2, sizeof(dk1));
}

Suite* pbkdf2_suite(void){
    Suite* s = suite_create("PBKDF2");
    TCase* tc_pbkdf2_same_as_OpenSSL = tcase_create("PBKDF2_same_as_in_OpenSSL");
    TCase* tc_pbkdf2_same_behaviour = tcase_create("PBKDF2_same_behavior");

    
    tcase_add_test(tc_pbkdf2_same_as_OpenSSL, test_pbkdf2_same_as_OpenSSL);
    tcase_add_test(tc_pbkdf2_same_behaviour, test_pbkdf2_same_behaviour);
    suite_add_tcase(s, tc_pbkdf2_same_as_OpenSSL);
    suite_add_tcase(s, tc_pbkdf2_same_behaviour);
    return s;
}

int main(void){
    int fail_count;
    Suite* s = pbkdf2_suite();
    SRunner* sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    fail_count = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (fail_count == 0) ? 0 : 1;
}