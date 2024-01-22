cmake_minimum_required(VERSION 3.14)
set(projectName CCPS)
project(${projectName} LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

if (WIN32)
    set(OpenSSL_PREFIX_PATH "D:\\OpenSSL")
elseif(UNIX)
    set(OpenSSL_PREFIX_PATH "/opt/OpenSSL")
else()
    message(FATAL_ERROR "不支持的操作系统类型")
endif ()

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(./include)
include_directories(./${projectName})
include_directories(${OpenSSL_PREFIX_PATH}/include/)

link_directories(${OpenSSL_PREFIX_PATH}/lib64/)

find_package(QT NAMES Qt6 Qt5 COMPONENTS Core Network REQUIRED)
find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Core Network REQUIRED)

add_library(
        ${projectName}
        SHARED
        CCPS/CCPS.cpp
        CCPS/CCPSManager.cpp
        tools/Dump.cpp
        tools/Key.cpp
        tools/IP.cpp
)

target_link_libraries(
        ${projectName}
        Qt${QT_VERSION_MAJOR}::Core
        Qt${QT_VERSION_MAJOR}::Network
        crypto
)
