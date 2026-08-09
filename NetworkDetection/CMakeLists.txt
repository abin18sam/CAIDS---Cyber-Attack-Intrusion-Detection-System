cmake_minimum_required(VERSION 3.10)
project(CAIDS_NetworkDetection CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# High-efficiency release build: optimize, and enable warnings so header
# parsing bugs surface at compile time rather than at runtime on live traffic.
if(NOT MSVC)
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
    add_compile_options(-Wall -Wextra)
else()
    add_compile_options(/W4)
endif()

find_package(PkgConfig)
if(PkgConfig_FOUND)
    pkg_check_modules(PCAP libpcap)
endif()
if(NOT PCAP_FOUND)
    find_library(PCAP_LIBRARIES pcap REQUIRED)
    set(PCAP_INCLUDE_DIRS "")
endif()

include_directories(${CMAKE_SOURCE_DIR}/include ${PCAP_INCLUDE_DIRS})

add_executable(caids_nids
    src/main.cpp
    src/PacketCapture.cpp
    src/PacketAnalyzer.cpp
    src/FlowAnalyzer.cpp
)

find_package(Threads REQUIRED)
target_link_libraries(caids_nids ${PCAP_LIBRARIES} Threads::Threads)
