cmake_minimum_required(VERSION 3.28)
project(CCPSCert C)

set(CMAKE_C_STANDARD 17)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(
        gen-ca-key
        gen-ca-key.c
)

target_link_libraries(
        gen-ca-key
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

add_executable(
        gen-cert
        gen-cert.c
)

if(WIN32)
    set(gen-cert-link ${LIB_EAY} ws2_32)
elseif(UNIX)
    set(gen-cert-link ${LIB_EAY})
else()
    message(FATAL_ERROR 未知平台)
endif()

target_link_libraries(
        gen-cert
        ${gen-cert-link}
)
