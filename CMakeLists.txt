cmake_minimum_required(VERSION 3.14)
set(projectName CCPSTest)
project(${projectName} LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(./include)
include_directories(./${projectName})

link_directories(libs)

find_package(QT NAMES Qt6 Qt5 COMPONENTS Widgets Network REQUIRED)
find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Widgets Network REQUIRED)

add_executable(
        ${projectName}
        main.cpp

        CCPSTest/CCPSTest.ui
        CCPSTest/CCPSTest.cpp

        NewConnect/NewConnect.cpp
        NewConnect/NewConnect.ui

        ShowMsg/ShowMsg.ui
        ShowMsg/ShowMsg.cpp

        CCPS/CCPS.cpp
        CCPS/CCPSManager.cpp
        tools/tools.cpp
)

target_link_libraries(
        ${projectName}
        Qt${QT_VERSION_MAJOR}::Widgets
        Qt${QT_VERSION_MAJOR}::Network
        key
)
