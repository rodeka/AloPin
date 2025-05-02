#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include "crypto/sha256.h"


START_TEST(test_sha256_check_behaviour){
    const unsigned char text[] = "Just test to check sha256 behaviour as normal sha256";
    const unsigned char hash_check[32] = {
        0x62, 0x86, 0x40, 0x32, 0xf8, 0x5f, 0x0b, 0x70,
        0xdd, 0xf4, 0x70, 0x7a, 0xf8, 0x04, 0xbc, 0xdf,
        0x43, 0xcd, 0x8a, 0xc0, 0x57, 0x5b, 0x62, 0x1d,
        0x9a, 0x2f, 0xc9, 0x27, 0x5b, 0x4d, 0xa0, 0x2f
    };

    unsigned char* hash = malloc(SHA256_DIGEST_LENGTH);
    ck_assert_ptr_nonnull(hash);

    sha256(text, sizeof(text), hash);

    if (memcmp(hash, hash_check, SHA256_DIGEST_LENGTH) != 0) {
        free(hash);
        ck_abort_msg("Hash does not match with check hash");
    }
    free(hash);
}

START_TEST(test_sha256_same_behaviour){
    const unsigned char text[] = "Just test to check sha256 on always same behaviour";

    unsigned char* hash1 = malloc(SHA256_DIGEST_LENGTH);
    ck_assert_ptr_nonnull(hash1);
    unsigned char* hash2 = malloc(SHA256_DIGEST_LENGTH);
    ck_assert_ptr_nonnull(hash2);

    sha256(text, sizeof(text), hash1);
    sha256(text, sizeof(text), hash2);

    if (memcmp(hash1, hash2, SHA256_DIGEST_LENGTH) != 0) {
        free(hash1);
        free(hash2);
        ck_abort_msg("Hashes do not match");
    }
    free(hash1);
    free(hash2);
}

Suite* hmac_sha256_suite(){
    Suite* s = suite_create("SHA256");

    TCase* tc_sha256_check_behaviour = tcase_create("SHA256_check_behaviour");
    tcase_add_test(tc_sha256_check_behaviour, test_sha256_check_behaviour);
    suite_add_tcase(s, tc_sha256_check_behaviour);

    TCase* tc_sha256_same_behaviour = tcase_create("SHA256_same_behavior");
    tcase_add_test(tc_sha256_same_behaviour, test_sha256_same_behaviour);
    suite_add_tcase(s, tc_sha256_same_behaviour);

    return s;
}

int main(){
    int fail_count;
    Suite* s = hmac_sha256_suite();
    SRunner* sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    fail_count = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (fail_count == 0) ? 0 : 1;
}