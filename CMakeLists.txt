cmake_minimum_required(VERSION 3.20)
project(AloPin
    VERSION 1.0.0
    LANGUAGES C CXX
)

if(NOT MSVC)
    message(FATAL_ERROR "This project support only MSCV")
endif()

# global settings
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# split layouts
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib/$<CONFIG>")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib/$<CONFIG>")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/$<CONFIG>")

# options
option(BUILD_TESTING "Build unit tests" ON)

# include dirs
set(INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)
set(STEAM_SDK ${PROJECT_SOURCE_DIR}/external/SteamworksSDK)

# crypto lib
add_library(crypto STATIC
    ${SRC_DIR}/crypto/pbkdf2.c
    ${SRC_DIR}/crypto/scrypt.c
    ${SRC_DIR}/crypto/sha256.c
    ${SRC_DIR}/crypto/hmac_sha256.c
)
target_include_directories(crypto
    PUBLIC
    $<BUILD_INTERFACE:${INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(crypto
    PUBLIC
    c_std_11
)

# proto lib
add_library(proto STATIC
    ${SRC_DIR}/proto/proto.c
)
target_include_directories(proto
    PUBLIC
    $<BUILD_INTERFACE:${INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(proto
    PUBLIC
    c_std_11
)

# main program
add_executable(alopin
    ${SRC_DIR}/alopin.cpp
)
target_include_directories(alopin
    PRIVATE
    ${INCLUDE_DIR}
    ${STEAM_SDK}/public
)
target_link_libraries(alopin
    PRIVATE
    crypto
    proto
    ${STEAM_SDK}/redistributable_bin/win64/steam_api64.lib
)
target_compile_features(alopin
    PRIVATE
    cxx_std_17
)

# copy steam_api64.dll
if(WIN32)
    add_custom_command(TARGET alopin POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${STEAM_SDK}/redistributable_bin/win64/steam_api64.dll"
        $<TARGET_FILE_DIR:alopin>
    )
else()
    message(FATAL_ERROR "Steamworks SDK is only supported on Windows")
endif()

# testing
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()
