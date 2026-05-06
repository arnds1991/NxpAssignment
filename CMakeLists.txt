cmake_minimum_required(VERSION 3.16)
project(ethsniff C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(ethsniff
    src/main.c
    src/dissect.c
)

target_include_directories(ethsniff PRIVATE src)

# ── Threads ────────────────────────────────────────────────────────────────
find_package(Threads REQUIRED)
target_link_libraries(ethsniff PRIVATE Threads::Threads)

# ── libpcap ────────────────────────────────────────────────────────────────
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PCAP QUIET libpcap)
endif()

if(PCAP_FOUND)
    target_include_directories(ethsniff PRIVATE ${PCAP_INCLUDE_DIRS})
    target_compile_options(ethsniff    PRIVATE ${PCAP_CFLAGS_OTHER})
    target_link_directories(ethsniff   PRIVATE ${PCAP_LIBRARY_DIRS})
    target_link_libraries(ethsniff     PRIVATE ${PCAP_LIBRARIES})
else()
    find_path(PCAP_INCLUDE_DIR  NAMES pcap.h)
    find_library(PCAP_LIBRARY   NAMES pcap)
    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
        message(FATAL_ERROR
            "libpcap not found.\n"
            "  Linux:  sudo apt-get install libpcap-dev\n"
            "  macOS:  brew install libpcap")
    endif()
    target_include_directories(ethsniff PRIVATE ${PCAP_INCLUDE_DIR})
    target_link_libraries(ethsniff      PRIVATE ${PCAP_LIBRARY})
endif()

# ── Frame injector (requires CAP_NET_RAW / root) ──────────────────────────
add_executable(send_frames
    tools/send_frames.c
)
target_include_directories(send_frames PRIVATE src)
