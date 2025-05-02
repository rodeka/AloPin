#include <check.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "crypto/scrypt.h"

START_TEST(test_scrypt_same_as_OpenSSL){
    const unsigned char password[] = {'1', '2', '3', '4'};
    const unsigned char salt[] = {0x29, 0xBE, 0xC0, 0xE9, 0x3E, 0x91, 0xAB, 0xB0};
    uint32_t N = 8192;
    uint32_t r = 8;
    uint32_t p = 1;
    uint8_t dk1[32];
    uint8_t dk2[32];

    scrypt((const unsigned char*)password, sizeof(password), (const unsigned char*)salt, sizeof(salt), N, r, p, dk1, sizeof(dk1));

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, NULL);
    if (!pctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_id failed\n");
        ck_abort();
    }
    
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive_init failed\n");
        EVP_PKEY_CTX_free(pctx);
        ck_abort();
    }
    
    if (EVP_PKEY_CTX_set1_pbe_pass(pctx, (const char*)password, sizeof(password)) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set1_pbe_pass failed\n");
        EVP_PKEY_CTX_free(pctx);
        ck_abort();
    }
    
    if (EVP_PKEY_CTX_set1_scrypt_salt(pctx, salt, sizeof(salt)) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set1_scrypt_salt failed\n");
        EVP_PKEY_CTX_free(pctx);
        ck_abort();
    }
    
    if (EVP_PKEY_CTX_set_scrypt_N(pctx, N) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_scrypt_N failed\n");
        EVP_PKEY_CTX_free(pctx);
        ck_abort();
    }
    
    if (EVP_PKEY_CTX_set_scrypt_r(pctx, r) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_scrypt_r failed\n");
        EVP_PKEY_CTX_free(pctx);
        ck_abort();
    }
    
    if (EVP_PKEY_CTX_set_scrypt_p(pctx, p) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_scrypt_p failed\n");
        EVP_PKEY_CTX_free(pctx);
        ck_abort();
    }
    
    size_t outlen = sizeof(dk2);
    if (EVP_PKEY_derive(pctx, dk2, &outlen) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive failed\n");
        EVP_PKEY_CTX_free(pctx);
        ck_abort();
    }
    EVP_PKEY_CTX_free(pctx);
    ck_assert_mem_eq(dk1, dk2, outlen);
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
    TCase* tc_scrypt_same_behaviour = tcase_create("SCRYPT_same_behavior");
    TCase* tc_scrypt_same_as_OpenSSL = tcase_create("SCRYPT_same_as_OpenSSL");
    
    tcase_add_test(tc_scrypt_same_as_OpenSSL, test_scrypt_same_as_OpenSSL);
    tcase_add_test(tc_scrypt_same_behaviour, test_scrypt_same_behaviour);
    suite_add_tcase(s, tc_scrypt_same_as_OpenSSL);
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