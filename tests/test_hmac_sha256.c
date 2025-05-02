#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include "crypto/hmac_sha256.h"


START_TEST(test_sha256_check_behaviour){
    const unsigned char text[] = "Just test to check hmac_sha256 behaviour as normal hmac_sha256"; // don't forget about null
    const unsigned char key[] = "Abra cadabra"; // same as prev
    const unsigned char hmac_hash_check[32] = {
        0x9d, 0x8c, 0x22, 0x4a, 0x0d, 0xf6, 0xcb, 0x8c,
        0xda, 0x2b, 0xd9, 0xd3, 0x4a, 0x23, 0x17, 0x78,
        0xfc, 0x8c, 0xc0, 0x61, 0x65, 0xc3, 0x23, 0xf9,
        0x5f, 0x52, 0xb0, 0x16, 0xe2, 0x00, 0xd3, 0x40
    };

    unsigned char* hmac_hash = malloc(SHA256_DIGEST_LENGTH);
    ck_assert_ptr_nonnull(hmac_hash);

    hmac_sha256(key, sizeof(key), text, sizeof(text), hmac_hash);

    if (memcmp(hmac_hash, hmac_hash_check, SHA256_DIGEST_LENGTH) != 0) {
        free(hmac_hash);
        ck_abort_msg("Hash does not match with check hmac_hash");
    }
    free(hmac_hash);
}

START_TEST(test_sha256_same_behaviour){
    const unsigned char text[] = "Just test to check hmac_sha256 on always same behaviour";

    unsigned char* hmac_hash1 = malloc(SHA256_DIGEST_LENGTH);
    ck_assert_ptr_nonnull(hmac_hash1);
    unsigned char* hmac_hash2 = malloc(SHA256_DIGEST_LENGTH);
    ck_assert_ptr_nonnull(hmac_hash2);

    sha256(text, sizeof(text), hmac_hash1);
    sha256(text, sizeof(text), hmac_hash2);

    if (memcmp(hmac_hash1, hmac_hash2, SHA256_DIGEST_LENGTH) != 0) {
        free(hmac_hash1);
        free(hmac_hash2);
        ck_abort_msg("Hmac hashes do not match");
    }
    free(hmac_hash1);
    free(hmac_hash2);
}

Suite* hmac_sha256_suite(){
    Suite* s = suite_create("HMAC_SHA256");

    TCase* tc_hmac_sha256_check_behaviour = tcase_create("SHA256_check_behaviour");
    tcase_add_test(tc_hmac_sha256_check_behaviour, test_sha256_check_behaviour);
    suite_add_tcase(s, tc_hmac_sha256_check_behaviour);

    TCase* tc_hmac_sha256_same_behaviour = tcase_create("SHA256_same_behavior");
    tcase_add_test(tc_hmac_sha256_same_behaviour, test_sha256_same_behaviour);
    suite_add_tcase(s, tc_hmac_sha256_same_behaviour);

    return s;
}

int main(){
    int fail_count;
    Suite* s = hmac_sha256_suite();
    SRunner* sr = srunner_create(s);

    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    fail_count = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (fail_count == 0) ? 0 : 1;
}