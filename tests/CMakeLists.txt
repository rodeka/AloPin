add_executable(test_pbkdf2 test_pbkdf2.c)
add_executable(test_scrypt test_scrypt.c)
add_executable(test_sha256 test_sha256.c)
add_executable(test_hmac_sha256 test_hmac_sha256.c)

if (WIN32)
    find_package(check CONFIG REQUIRED)             # provided by vcpkg
    set(CHECK_TARGET Check::checkShared)            # or Check::checkShared
else()
    pkg_check_modules(CHECK REQUIRED IMPORTED_TARGET check)
    set(CHECK_TARGET PkgConfig::CHECK)
endif()

# test pbkdf2
target_link_libraries(test_pbkdf2
    PRIVATE crypto
    PRIVATE ${CHECK_TARGET}                         # check framework
)
target_include_directories(test_pbkdf2
    PRIVATE ${INCLUDE_DIR}
)

# test scrypt
target_link_libraries(test_scrypt
    PRIVATE crypto
    PRIVATE ${CHECK_TARGET}                         # check framework
)
target_include_directories(test_scrypt
    PRIVATE ${INCLUDE_DIR}
)

# test sha256
target_link_libraries(test_sha256
    PRIVATE crypto
    PRIVATE ${CHECK_TARGET}                         # check framework
)
target_include_directories(test_sha256
    PRIVATE ${INCLUDE_DIR}
)

# test hmac_sha256
target_link_libraries(test_hmac_sha256
    PRIVATE crypto
    PRIVATE ${CHECK_TARGET}                         # check framework
)
target_include_directories(test_hmac_sha256
    PRIVATE ${INCLUDE_DIR}
)


add_test(NAME pbkdf2_unit COMMAND test_pbkdf2)
add_test(NAME scrypt_unit COMMAND test_scrypt)
add_test(NAME sha256_unit COMMAND test_sha256)
add_test(NAME hmac_sha256_unit COMMAND test_hmac_sha256)
