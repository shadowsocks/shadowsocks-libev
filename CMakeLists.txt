cmake_minimum_required(VERSION 3.5)

set(PROJECT_NAME shadowsocks-libev)
set(RELEASE_DATE 2026-02-09)
set(PROJECT_VERSION "3.3.6")
set(PROJECT_DESC "a lightweight secured socks5 proxy")
set(PROJECT_URL "https://shadowsocks.org")
set(PROJECT_ISSUES_URL "https://github.com/shadowsocks/shadowsocks-libev")
project(${PROJECT_NAME} VERSION ${PROJECT_VERSION})

include(GNUInstallDirs)

# Compiler flags matching autotools
# Note: -Werror is applied per-target in src/CMakeLists.txt to avoid
# breaking bundled submodules (libcork, libipset, libbloom)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -D_GNU_SOURCE")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O2 -Wall -Wno-deprecated-declarations -fno-strict-aliasing")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)
set(RUNTIME_SHARED_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/shared/bin)

set(CMAKE_MACOSX_RPATH TRUE)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif ()
# Detect linux
if (UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif ()

message(STATUS "Running cmake version ${CMAKE_VERSION}")

option(WITH_STATIC "build with static libraries." ON)
option(WITH_EMBEDDED_SRC "build with embedded libcork, libipset, and libbloom source." ON)
option(ENABLE_CONNMARKTOS "Enable saved connmark to IP TOS QoS feature" OFF)
option(ENABLE_NFTABLES "Report malicious IP to nftables" OFF)

# When choose to not use embedded libcork, libipset and libbloom, use libs shipped by system
if (NOT WITH_EMBEDDED_SRC)
    set(USE_SYSTEM_SHARED_LIB TRUE)
endif ()

# Find dependencies via Find modules
find_package(PCRE2 REQUIRED)
find_package(MbedTLS REQUIRED)
find_package(Sodium REQUIRED)
find_package(Cares REQUIRED)

# Connmarktos support
if(ENABLE_CONNMARKTOS)
    if(NOT LINUX)
        message(FATAL_ERROR "connmarktos is only supported on Linux")
    endif()
    find_library(NETFILTER_CONNTRACK_LIB netfilter_conntrack)
    find_library(NFNETLINK_LIB nfnetlink)
    if(NOT NETFILTER_CONNTRACK_LIB)
        message(FATAL_ERROR "--enable-connmarktos specified but libnetfilter_conntrack not found")
    endif()
    set(USE_NFCONNTRACK_TOS 1)
    message(STATUS "Connmarktos enabled")
endif()

# Nftables support
if(ENABLE_NFTABLES)
    if(NOT LINUX)
        message(FATAL_ERROR "nftables is only supported on Linux")
    endif()
    find_library(MNL_LIB mnl)
    find_library(NFTNL_LIB nftnl)
    if(NOT MNL_LIB OR NOT NFTNL_LIB)
        message(FATAL_ERROR "--enable-nftables specified but libmnl or libnftnl not found")
    endif()
    set(USE_NFTABLES 1)
    message(STATUS "Nftables enabled")
endif()

# Run platform tests
include(${PROJECT_SOURCE_DIR}/cmake/configure.cmake)
configure_file(${PROJECT_SOURCE_DIR}/cmake/config.h.cmake ${PROJECT_BINARY_DIR}/src/config.h)
add_definitions(-I${PROJECT_BINARY_DIR}/src)
add_definitions(-DHAVE_CONFIG_H)

# pkg-config
configure_file(
        ${PROJECT_SOURCE_DIR}/cmake/shadowsocks-libev.pc.cmake
        ${PROJECT_BINARY_DIR}/pkgconfig/shadowsocks-libev.pc
        @ONLY
)
install(FILES
        ${PROJECT_BINARY_DIR}/pkgconfig/shadowsocks-libev.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
        )

if (WITH_EMBEDDED_SRC)
# We need libcork,libipset headers
include_directories(libcork/include)
include_directories(libipset/include)
include_directories(libbloom/murmur2)
include_directories(libbloom)

set(LIBCORK_SOURCE
        libcork/src/libcork/cli/commands.c
        libcork/src/libcork/core/allocator.c
        libcork/src/libcork/core/error.c
        libcork/src/libcork/core/gc.c
        libcork/src/libcork/core/hash.c
        libcork/src/libcork/core/ip-address.c
        libcork/src/libcork/core/mempool.c
        libcork/src/libcork/core/timestamp.c
        libcork/src/libcork/core/u128.c
        libcork/src/libcork/core/version.c
        libcork/src/libcork/ds/array.c
        libcork/src/libcork/ds/bitset.c
        libcork/src/libcork/ds/buffer.c
        libcork/src/libcork/ds/dllist.c
        libcork/src/libcork/ds/file-stream.c
        libcork/src/libcork/ds/hash-table.c
        libcork/src/libcork/ds/managed-buffer.c
        libcork/src/libcork/ds/ring-buffer.c
        libcork/src/libcork/ds/slice.c
        libcork/src/libcork/posix/directory-walker.c
        libcork/src/libcork/posix/env.c
        libcork/src/libcork/posix/exec.c
        libcork/src/libcork/posix/files.c
        libcork/src/libcork/posix/process.c
        libcork/src/libcork/pthreads/thread.c
        )
if (NOT MINGW)
set(LIBCORK_SOURCE ${LIBCORK_SOURCE} libcork/src/libcork/posix/subprocess.c)
else ()
set(LIBCORK_SOURCE ${LIBCORK_SOURCE} libcork/src/libcork/posix/mingw.c)
endif ()

add_library(cork STATIC ${LIBCORK_SOURCE})
target_compile_definitions(cork PUBLIC -DCORK_API=CORK_LOCAL)
if (MINGW)
target_link_libraries(cork ws2_32)
endif ()

set(LIBIPSET_SOURCE
        libipset/src/libipset/general.c
        libipset/src/libipset/bdd/assignments.c
        libipset/src/libipset/bdd/basics.c
        libipset/src/libipset/bdd/bdd-iterator.c
        libipset/src/libipset/bdd/expanded.c
        libipset/src/libipset/bdd/reachable.c
        libipset/src/libipset/bdd/read.c
        libipset/src/libipset/bdd/write.c
        libipset/src/libipset/map/allocation.c
        libipset/src/libipset/map/inspection.c
        libipset/src/libipset/map/ipv4_map.c
        libipset/src/libipset/map/ipv6_map.c
        libipset/src/libipset/map/storage.c
        libipset/src/libipset/set/allocation.c
        libipset/src/libipset/set/inspection.c
        libipset/src/libipset/set/ipv4_set.c
        libipset/src/libipset/set/ipv6_set.c
        libipset/src/libipset/set/iterator.c
        libipset/src/libipset/set/storage.c
        )

add_library(ipset STATIC ${LIBIPSET_SOURCE})

set(LIBBLOOM_SOURCE
        libbloom/bloom.c
        libbloom/murmur2/MurmurHash2.c
        )

add_library(bloom STATIC ${LIBBLOOM_SOURCE})
target_link_libraries(ipset cork bloom)
endif ()

add_subdirectory(src)
add_subdirectory(doc)

# Testing
include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# Install ss-nat on Linux
if(LINUX)
    install(PROGRAMS src/ss-nat DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# Install ss-setup TUI tool
install(PROGRAMS scripts/ss-setup.sh DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME ss-setup)
