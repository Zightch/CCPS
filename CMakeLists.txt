cmake_minimum_required(VERSION 3.28)

project(cert C)
set(CMAKE_C_STANDARD 17)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})

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

add_library(
        key
        SHARED
        key/jni/key.c
)

if(WIN32)
    set(key-link E:/OpenSSL/lib64/libcrypto.a ws2_32 crypt32)
elseif(UNIX)
    set(key-link E:/OpenSSL/lib64/libcrypto.a)
else()
    message(FATAL_ERROR 未知平台)
endif()

target_link_libraries(
        key
        ${key-link}
)
