cmake_minimum_required(VERSION 3.20)
project(AloPin C)

# common flags
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Werror)

# find libs
find_package(OpenSSL 1.1 REQUIRED COMPONENTS Crypto)

# link pbkdf2 lib
add_library(pbkdf2 STATIC
    src/crypto/pbkdf2.c
)
target_include_directories(pbkdf2
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(pbkdf2
    PUBLIC OpenSSL::Crypto
)

# link scrypt lib
add_library(scrypt STATIC
    src/crypto/scrypt.c
)
target_include_directories(scrypt
    PUBLIC ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(scrypt
    PUBLIC OpenSSL::Crypto
)
target_link_libraries(scrypt
    PUBLIC pbkdf2
)

# sanit
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(pbkdf2 PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(scrypt PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options   (pbkdf2 PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options   (scrypt PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

# tests
option(BUILD_TESTING "Build unit tests" ON)
include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
