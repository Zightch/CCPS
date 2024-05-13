cmake_minimum_required(VERSION 3.28)
project(CCPSCert C)

set(CMAKE_C_STANDARD 17)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(
        genCAKey
        genCAKey.c
)

target_link_libraries(
        genCAKey
        ${LIB_EAY}
)

add_executable(
        sign
        sign.c
)

target_link_libraries(
        sign
        ${LIB_EAY}
)

add_executable(
        verify
        verify.c
)

target_link_libraries(
        verify
        ${LIB_EAY}
)
