cmake_minimum_required(VERSION 3.5)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


set(AID_VERSION_MAJOR 0)
set(AID_VERSION_MINOR 1)
set(AID_VERSION_PATCH 0)
set(AID_VERSION "${AID_VERSION_MAJOR}.${AID_VERSION_MINOR}.${AID_VERSION_PATCH}")

project(android-infection-detector VERSION ${AID_VERSION} LANGUAGES C CXX)

find_package(LIEF REQUIRED)
find_package(Boost 1.38 COMPONENTS graph system REQUIRED)
find_package(nlohmann_json 3.6.1 REQUIRED)

add_executable(aid
    # dalvik
    ${CMAKE_CURRENT_LIST_DIR}/src/dex/disasm.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/dex/lookup.c
    # obfuscation detection
    ${CMAKE_CURRENT_LIST_DIR}/src/obfus.cpp
    # graph stuff
    ${CMAKE_CURRENT_LIST_DIR}/src/graph/conn.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/graph/dalvik.cpp
    # server
    ${CMAKE_CURRENT_LIST_DIR}/src/server/server.cpp
    # main
    ${CMAKE_CURRENT_LIST_DIR}/src/main.cpp
)

target_include_directories(aid
    PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include
)

target_link_libraries(aid
    LIEF::LIEF
    Boost::graph
    Boost::system
    nlohmann_json::nlohmann_json
)
