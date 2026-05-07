cmake_minimum_required(VERSION 3.16)
project(ethsniff C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)


add_executable(ethsniff
    src/main.c
    src/dissect.c
    src/ring.c
)

target_include_directories(ethsniff PRIVATE src)

install(TARGETS ethsniff RUNTIME DESTINATION .)

add_custom_command(TARGET ethsniff POST_BUILD
    COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR} --prefix ${CMAKE_SOURCE_DIR}/out
)

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

# ── Frame injector (Linux: AF_PACKET; macOS: BPF) ─────────────────────────
# send_frames.c uses #ifdef __linux__ / #elif __APPLE__ guards internally;
# no separate source file is needed.  The only platform difference at the
# CMake level is the extra frameworks required on macOS.
add_executable(send_frames
    tools/send_frames.c
)
target_include_directories(send_frames PRIVATE src)

if(APPLE)
    # BPF access on macOS does not require an extra library, but the binary
    # must be code-signed or run as root to open /dev/bpf*.
    # CoreFoundation is pulled in transitively by libpcap on macOS; list it
    # explicitly so the linker finds it even without pkg-config.
    find_library(COREFOUNDATION_LIB CoreFoundation)
    if(COREFOUNDATION_LIB)
        target_link_libraries(send_frames PRIVATE ${COREFOUNDATION_LIB})
    endif()
elseif(UNIX)
    # Linux: no additional libraries needed beyond libc.
endif()
