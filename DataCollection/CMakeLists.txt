cmake_minimum_required(VERSION 3.10)
project(CAIDS_DataCollection CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
add_compile_options(-Wall -Wextra)

find_package(PkgConfig)
if(PkgConfig_FOUND)
    pkg_check_modules(PCAP libpcap)
endif()
if(NOT PCAP_FOUND)
    find_library(PCAP_LIBRARIES pcap REQUIRED)
    set(PCAP_INCLUDE_DIRS "")
endif()

include_directories(${CMAKE_SOURCE_DIR}/include ${PCAP_INCLUDE_DIRS})

add_executable(caids_collector
    src/main.cpp
    src/PacketCapture.cpp
    src/RotatingPcapWriter.cpp
    src/RotatingMetadataWriter.cpp
    src/Config.cpp
    src/DiskGuard.cpp
)

find_package(Threads REQUIRED)
target_link_libraries(caids_collector ${PCAP_LIBRARIES} Threads::Threads)
