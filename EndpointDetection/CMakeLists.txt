cmake_minimum_required(VERSION 3.14)
project(caids_endpoint_agent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

set(SOURCES
    src/main.cpp
    src/EndpointEvent.cpp
    src/EventCollector.cpp
    src/ProcessMonitor.cpp
    src/SuspiciousProcessDetector.cpp
    src/KeyloggerDetector.cpp
)

add_executable(caids_endpoint_agent ${SOURCES})

if(WIN32)
    target_link_libraries(caids_endpoint_agent PRIVATE Advapi32 Psapi)
else()
    target_link_libraries(caids_endpoint_agent PRIVATE pthread)
endif()

# Installation target
install(TARGETS caids_endpoint_agent DESTINATION bin)
