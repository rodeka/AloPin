find_package(PkgConfig REQUIRED)
pkg_check_modules(CHECK REQUIRED IMPORTED_TARGET check)

add_executable(test_pbkdf2 test_pbkdf2.c)

target_link_libraries(test_pbkdf2
    PRIVATE pbkdf2
            OpenSSL::Crypto             # OpenSSL 
            PkgConfig::CHECK            # check framework

)

target_include_directories(test_pbkdf2
    PRIVATE ${PROJECT_SOURCE_DIR}/include
)

add_test(NAME pbkdf2_unit COMMAND test_pbkdf2)
