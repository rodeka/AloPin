add_executable(test_pbkdf2 test_pbkdf2.c)
add_executable(test_scrypt test_scrypt.c)

if (WIN32)
    find_package(check CONFIG REQUIRED)             # provided by vcpkg
    set(CHECK_TARGET Check::checkShared)            # or Check::checkShared
else()
    pkg_check_modules(CHECK REQUIRED IMPORTED_TARGET check)
    set(CHECK_TARGET PkgConfig::CHECK)
endif()

target_link_libraries(test_pbkdf2
    PRIVATE crypto
    PRIVATE OpenSSL::Crypto                         # OpenSSL 
    PRIVATE ${CHECK_TARGET}                         # check framework
)

target_link_libraries(test_scrypt
    PRIVATE crypto
    PRIVATE OpenSSL::Crypto                         # OpenSSL 
    PRIVATE ${CHECK_TARGET}                         # check framework
)

target_include_directories(test_pbkdf2
    PRIVATE ${INCLUDE_DIR}
)

target_include_directories(test_scrypt
    PRIVATE ${INCLUDE_DIR}
)

add_test(NAME pbkdf2_unit COMMAND test_pbkdf2)
add_test(NAME scrypt_unit COMMAND test_scrypt)
