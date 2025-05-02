cmake_minimum_required(VERSION 3.20)
project(AloPin C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib/$<CONFIG>")

set(SOURCE_CODE_DIR ${PROJECT_SOURCE_DIR}/src)
set(INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)

# crypto lib
add_library(crypto STATIC
    ${SOURCE_CODE_DIR}/crypto/pbkdf2.c
    ${SOURCE_CODE_DIR}/crypto/scrypt.c
    ${SOURCE_CODE_DIR}/crypto/sha256.c
    ${SOURCE_CODE_DIR}/crypto/hmac_sha256.c
)

target_include_directories(crypto
    PRIVATE ${INCLUDE_DIR}
)

# link proto lib
add_library(proto STATIC
    ${SOURCE_CODE_DIR}/proto/proto.c
)

target_include_directories(proto
    PRIVATE ${INCLUDE_DIR}
)

# main prog
set(STEAM_SDK ${PROJECT_SOURCE_DIR}/external/SteamworksSDK)

add_executable(alopin 
    ${SOURCE_CODE_DIR}/alopin.cpp
)
target_include_directories(alopin 
    PRIVATE ${INCLUDE_DIR}
    PRIVATE ${STEAM_SDK}/public
)
target_link_libraries(alopin
    PRIVATE proto
    PRIVATE crypto
    PRIVATE ${STEAM_SDK}/redistributable_bin/win64/steam_api64.lib
)

if(WIN32)
  add_custom_command(TARGET alopin POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${STEAM_SDK}/redistributable_bin/win64/steam_api64.dll"
      $<TARGET_FILE_DIR:alopin>
  )

  add_custom_command(TARGET alopin POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${PROJECT_SOURCE_DIR}/src/steam_appid.txt"
    $<TARGET_FILE_DIR:alopin>
    )

else()
    message(FATAL_ERROR "ONLY WINDOWS STEAM SDK!")
endif()

# tests
option(BUILD_TESTING "Build unit tests" ON)
include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
