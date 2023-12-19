cmake_minimum_required(VERSION 3.14)
set(projectName CCPS)
project(${projectName} LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

if (WIN32)
    set(CMAKE_PREFIX_PATH "E:\\Qt\\6.6.0\\mingw_64\\lib\\cmake")
elseif(UNIX)
    set(CMAKE_PREFIX_PATH "/opt/Qt/6.6.0/gcc_64/lib/cmake")
endif ()

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(./include)
include_directories(./${projectName})

link_directories(libs)

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
