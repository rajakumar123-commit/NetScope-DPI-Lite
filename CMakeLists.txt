cmake_minimum_required(VERSION 3.16)
project(NetScopeDPI VERSION 1.0 LANGUAGES CXX)

# ============================================================================
# Compiler settings
# ============================================================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# ============================================================================
# Dependencies
# ============================================================================
find_package(Threads REQUIRED)

# ============================================================================
# Include paths
# ============================================================================
include_directories(${CMAKE_SOURCE_DIR}/include)

# ============================================================================
# Source files
# ============================================================================
set(SOURCES
    src/main.cpp
    src/types.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
    src/load_balancer.cpp
    src/fast_path.cpp
    src/metrics.cpp
    src/logger.cpp
)

# ============================================================================
# Main executable
# ============================================================================
add_executable(netscope_dpi ${SOURCES})

target_link_libraries(netscope_dpi
    PRIVATE
        Threads::Threads
)

target_compile_options(netscope_dpi PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-O2 -Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /O2>
)

# ============================================================================
# Test executables (optional — only built if test sources exist)
# ============================================================================
set(TEST_SOURCES_PARSER tests/test_parser.cpp
    src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp src/logger.cpp)
set(TEST_SOURCES_SNI    tests/test_sni.cpp
    src/types.cpp src/sni_extractor.cpp src/logger.cpp)

if(EXISTS ${CMAKE_SOURCE_DIR}/tests/test_parser.cpp)
    add_executable(test_parser ${TEST_SOURCES_PARSER})
    target_link_libraries(test_parser PRIVATE Threads::Threads)
    target_include_directories(test_parser PRIVATE ${CMAKE_SOURCE_DIR}/include)
endif()

if(EXISTS ${CMAKE_SOURCE_DIR}/tests/test_sni.cpp)
    add_executable(test_sni ${TEST_SOURCES_SNI})
    target_link_libraries(test_sni PRIVATE Threads::Threads)
    target_include_directories(test_sni PRIVATE ${CMAKE_SOURCE_DIR}/include)
endif()

# ============================================================================
# Install
# ============================================================================
install(TARGETS netscope_dpi DESTINATION bin)
install(FILES rules.conf DESTINATION etc/netscope)

# ============================================================================
# Print build summary
# ============================================================================
message(STATUS "===== NetScope DPI Lite =====")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "CXX standard: C++${CMAKE_CXX_STANDARD}")
message(STATUS "Sources: ${CMAKE_SOURCE_DIR}/src/")
message(STATUS "To build:")
message(STATUS "  mkdir build && cd build")
message(STATUS "  cmake .. && make -j$(nproc)")
message(STATUS "  ./netscope_dpi --pcap ../pcaps/test_dpi.pcap")
