# find testing framework
if(WIN32)
  find_package(check CONFIG REQUIRED) # provided by vcpkg
  set(CheckLib Check::checkShared)
else()
  message(FATAL_ERROR "Tests work only on windows 'cause it's win only app")
endif()

# List of test executables (each .c file under this directory)
set(TESTS
  test_pbkdf2
  test_scrypt
  test_sha256
  test_hmac_sha256
)

foreach(test IN LISTS TESTS)
  add_executable(${test} ${test}.c)

  target_link_libraries(${test}
    PRIVATE
    crypto # inherits PUBLIC include dirs from crypto target
    ${CheckLib} # the Check testing framework
  )

  # Register with CTest
  add_test(NAME ${test}_unit COMMAND ${test})
endforeach()
