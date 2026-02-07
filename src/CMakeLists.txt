# redir need linux/* stuff
if (LINUX)
    option(WITH_SS_REDIR "Build ss-redir" ON)
    option(WITH_SS_MANAGER "Build ss-manager" ON)
else ()
    option(WITH_SS_REDIR "Build ss-redir" OFF)
    option(WITH_SS_MANAGER "Build ss-manager" OFF)
endif ()


set(SS_ACL_SOURCE
        acl.c
        rule.c
        )

set(SS_CRYPTO_SOURCE
        crypto.c
        aead.c
        stream.c
        base64.c
        )

set(SS_PLUGIN_SOURCE
        plugin.c
        )

set(SS_SHARED_SOURCES
        ppbloom.c
        utils.c
        jconf.c
        json.c
        netutils.c
        )
if (MINGW)
set(SS_SHARED_SOURCES ${SS_SHARED_SOURCES} winsock.c)
endif ()

set(LIBSHADOWSOCKS_LIBEV_SOURCE
        ${SS_SHARED_SOURCES}
        udprelay.c
        cache.c
        local.c
        ${SS_CRYPTO_SOURCE}
        ${SS_PLUGIN_SOURCE}
        ${SS_ACL_SOURCE}
        )

set(SS_LOCAL_SOURCE
        ${LIBSHADOWSOCKS_LIBEV_SOURCE}

        )

set(SS_TUNNEL_SOURCE
        ${SS_SHARED_SOURCES}
        udprelay.c
        cache.c
        tunnel.c
        ${SS_CRYPTO_SOURCE}
        ${SS_PLUGIN_SOURCE}
        )

set(SS_SERVER_SOURCE
        ${SS_SHARED_SOURCES}
        udprelay.c
        cache.c
        resolv.c
        server.c
        ${SS_CRYPTO_SOURCE}
        ${SS_PLUGIN_SOURCE}
        ${SS_ACL_SOURCE}
        )

set(SS_MANAGER_SOURCE
        ${SS_SHARED_SOURCES}
        manager.c
        )

set(SS_REDIR_SOURCE
        ${SS_SHARED_SOURCES}
        udprelay.c
        cache.c
        redir.c
        ${SS_CRYPTO_SOURCE}
        ${SS_PLUGIN_SOURCE}
        )

# Apply -Werror only to project sources (not bundled submodules)
set(SS_WERROR_FLAGS -Werror)

# Include directories from Find modules
# MbedTLS must come first to avoid conflicts with other mbedtls versions
# that may be in /opt/homebrew/include (e.g. mbedtls 4.x vs 3.x)
include_directories(BEFORE ${MBEDTLS_INCLUDE_DIRS})
include_directories(${SODIUM_INCLUDE_DIRS})
include_directories(${PCRE2_INCLUDE_DIRS})
include_directories(${CARES_INCLUDE_DIRS})

# Extract mbedTLS lib dir to ensure static/shared libs come from same version
get_filename_component(_MBEDTLS_LIB_DIR "${MBEDTLS_CRYPTO_LIBRARY}" DIRECTORY)

if (WITH_STATIC)
find_library(LIBSODIUM libsodium.a)
find_library(LIBMBEDTLS libmbedtls.a HINTS ${_MBEDTLS_LIB_DIR} NO_DEFAULT_PATH)
find_library(LIBMBEDTLS libmbedtls.a)
find_library(LIBMBEDCRYPTO libmbedcrypto.a HINTS ${_MBEDTLS_LIB_DIR} NO_DEFAULT_PATH)
find_library(LIBMBEDCRYPTO libmbedcrypto.a)
find_library(LIBEV libev.a)
find_library(LIBUDNS libcares.a)
find_library(LIBPCRE2 libpcre2-8.a)

# Dependencies we need for static and shared
list(APPEND DEPS
        m
        bloom
        ${LIBEV}
        ${LIBUDNS}
        ${LIBPCRE2}
        ${LIBSODIUM}
        ${LIBMBEDTLS}
        ${LIBMBEDCRYPTO}
        )

if (MINGW)
list(APPEND DEPS ws2_32 iphlpapi)
add_compile_definitions(CARES_STATICLIB PCRE2_STATIC)
endif ()
endif ()

find_library(LIBSODIUM_SHARED sodium)
find_library(LIBMBEDTLS_SHARED mbedtls HINTS ${_MBEDTLS_LIB_DIR} NO_DEFAULT_PATH)
find_library(LIBMBEDTLS_SHARED mbedtls)
find_library(LIBMBEDCRYPTO_SHARED mbedcrypto HINTS ${_MBEDTLS_LIB_DIR} NO_DEFAULT_PATH)
find_library(LIBMBEDCRYPTO_SHARED mbedcrypto)
find_library(LIBEV_SHARED ev)
find_library(LIBUDNS_SHARED cares)
find_library(LIBPCRE2_SHARED pcre2-8)

if (WITH_EMBEDDED_SRC)
list(APPEND DEPS_SHARED
        m
        bloom-shared
        cork-shared
        ipset-shared
        ${LIBEV_SHARED}
        ${LIBUDNS_SHARED}
        ${LIBPCRE2_SHARED}
        ${LIBSODIUM_SHARED}
        ${LIBMBEDTLS_SHARED}
        ${LIBMBEDCRYPTO_SHARED}
        )
else ()
find_library(LIBBLOOM_SHARED bloom)
find_library(LIBCORK_SHARED cork)
find_library(LIBCORKIPSET_SHARED corkipset)
list(APPEND DEPS_SHARED
        m
        ${LIBBLOOM_SHARED}
        ${LIBCORK_SHARED}
        ${LIBCORKIPSET_SHARED}
        ${LIBEV_SHARED}
        ${LIBUDNS_SHARED}
        ${LIBPCRE2_SHARED}
        ${LIBSODIUM_SHARED}
        ${LIBMBEDTLS_SHARED}
        ${LIBMBEDCRYPTO_SHARED}
        )
endif ()

# Connmarktos/nftables libraries for ss-server
if(ENABLE_CONNMARKTOS)
    list(APPEND DEPS_CONNMARKTOS ${NETFILTER_CONNTRACK_LIB})
    if(NFNETLINK_LIB)
        list(APPEND DEPS_CONNMARKTOS ${NFNETLINK_LIB})
    endif()
endif()
if(ENABLE_NFTABLES)
    list(APPEND DEPS_NFTABLES ${MNL_LIB} ${NFTNL_LIB})
endif()

find_package (Threads)

if (WITH_STATIC)
# ------------------------------------------------------------------
# Static
# By default we use normal name for static, all shared targets will add a `-shared' suffix
add_executable(ss-server ${SS_SERVER_SOURCE})
add_executable(ss-tunnel ${SS_TUNNEL_SOURCE})
if (WITH_SS_MANAGER)
    add_executable(ss-manager ${SS_MANAGER_SOURCE})
else ()
    add_executable(ss-manager EXCLUDE_FROM_ALL ${SS_MANAGER_SOURCE})
endif ()
add_executable(ss-local ${SS_LOCAL_SOURCE})
if (WITH_SS_REDIR)
    add_executable(ss-redir ${SS_REDIR_SOURCE})
else ()
    add_executable(ss-redir EXCLUDE_FROM_ALL ${SS_REDIR_SOURCE})
endif ()
add_library(shadowsocks-libev STATIC ${LIBSHADOWSOCKS_LIBEV_SOURCE})


target_compile_definitions(ss-server PUBLIC -DMODULE_REMOTE)
target_compile_definitions(ss-tunnel PUBLIC -DMODULE_TUNNEL)
target_compile_definitions(ss-manager PUBLIC -DMODULE_MANAGER)
target_compile_definitions(ss-local PUBLIC -DMODULE_LOCAL)
target_compile_definitions(ss-redir PUBLIC -DMODULE_REDIR)
target_compile_definitions(shadowsocks-libev PUBLIC -DMODULE_LOCAL -DLIB_ONLY)

target_compile_options(ss-server PRIVATE ${SS_WERROR_FLAGS})
target_compile_options(ss-tunnel PRIVATE ${SS_WERROR_FLAGS})
target_compile_options(ss-manager PRIVATE ${SS_WERROR_FLAGS})
target_compile_options(ss-local PRIVATE ${SS_WERROR_FLAGS})
target_compile_options(ss-redir PRIVATE ${SS_WERROR_FLAGS})
target_compile_options(shadowsocks-libev PRIVATE ${SS_WERROR_FLAGS})

# Connmarktos/nftables compile definitions
if(ENABLE_CONNMARKTOS)
    target_compile_definitions(ss-server PUBLIC -DUSE_NFCONNTRACK_TOS)
endif()
if(ENABLE_NFTABLES)
    target_compile_definitions(ss-server PUBLIC -DUSE_NFTABLES)
endif()

target_include_directories(shadowsocks-libev PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(ss-server cork ipset ${DEPS} ${DEPS_CONNMARKTOS} ${DEPS_NFTABLES})
target_link_libraries(ss-tunnel cork ${DEPS})
target_link_libraries(ss-manager m bloom cork ${LIBEV} ${LIBUDNS})
target_link_libraries(ss-local cork ipset ${DEPS})
target_link_libraries(ss-redir cork ipset ${DEPS})
target_link_libraries(shadowsocks-libev cork ipset ${DEPS})
endif ()

# ------------------------------------------------------------------
# Shared
# Shared target will have a `-shared' suffix
# All shared dependency also have `-shared' suffix
# For shared binary, we still use the same name as static, without `-shared', but will output to shared directory
add_executable(ss-server-shared ${SS_SERVER_SOURCE})
add_executable(ss-tunnel-shared ${SS_TUNNEL_SOURCE})
if (WITH_SS_MANAGER)
    add_executable(ss-manager-shared ${SS_MANAGER_SOURCE})
else ()
    add_executable(ss-manager-shared EXCLUDE_FROM_ALL ${SS_MANAGER_SOURCE})
endif ()
add_executable(ss-local-shared ${SS_LOCAL_SOURCE})
if (WITH_SS_REDIR)
    add_executable(ss-redir-shared ${SS_REDIR_SOURCE})
else ()
    add_executable(ss-redir-shared EXCLUDE_FROM_ALL ${SS_REDIR_SOURCE})
endif ()
add_library(shadowsocks-libev-shared SHARED ${LIBSHADOWSOCKS_LIBEV_SOURCE})

target_compile_definitions(ss-server-shared PUBLIC -DMODULE_REMOTE)
target_compile_definitions(ss-tunnel-shared PUBLIC -DMODULE_TUNNEL)
target_compile_definitions(ss-manager-shared PUBLIC -DMODULE_MANAGER)
target_compile_definitions(ss-local-shared PUBLIC -DMODULE_LOCAL)
target_compile_definitions(ss-redir-shared PUBLIC -DMODULE_REDIR)
target_compile_definitions(shadowsocks-libev-shared PUBLIC -DMODULE_LOCAL -DLIB_ONLY)

target_compile_options(ss-server-shared PRIVATE ${SS_WERROR_FLAGS})
target_compile_options(ss-tunnel-shared PRIVATE ${SS_WERROR_FLAGS})
target_compile_options(ss-manager-shared PRIVATE ${SS_WERROR_FLAGS})
target_compile_options(ss-local-shared PRIVATE ${SS_WERROR_FLAGS})
target_compile_options(ss-redir-shared PRIVATE ${SS_WERROR_FLAGS})
target_compile_options(shadowsocks-libev-shared PRIVATE ${SS_WERROR_FLAGS})

# Connmarktos/nftables compile definitions for shared
if(ENABLE_CONNMARKTOS)
    target_compile_definitions(ss-server-shared PUBLIC -DUSE_NFCONNTRACK_TOS)
endif()
if(ENABLE_NFTABLES)
    target_compile_definitions(ss-server-shared PUBLIC -DUSE_NFTABLES)
endif()

target_include_directories(shadowsocks-libev-shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(ss-server-shared ${DEPS_SHARED} ${DEPS_CONNMARKTOS} ${DEPS_NFTABLES})
target_link_libraries(ss-tunnel-shared ${DEPS_SHARED})
target_link_libraries(ss-manager-shared ${CMAKE_THREAD_LIBS_INIT} ${LIBEV_SHARED} ${LIBUDNS_SHARED} ${DEPS_SHARED})
target_link_libraries(ss-local-shared ${DEPS_SHARED})
target_link_libraries(ss-redir-shared ${DEPS_SHARED})
target_link_libraries(shadowsocks-libev-shared ${DEPS_SHARED})

set_target_properties(ss-server-shared PROPERTIES OUTPUT_NAME ss-server)
set_target_properties(ss-tunnel-shared PROPERTIES OUTPUT_NAME ss-tunnel)
set_target_properties(ss-manager-shared PROPERTIES OUTPUT_NAME ss-manager)
set_target_properties(ss-local-shared PROPERTIES OUTPUT_NAME ss-local)
set_target_properties(ss-redir-shared PROPERTIES OUTPUT_NAME ss-redir)

set_target_properties(ss-server-shared ss-tunnel-shared ss-manager-shared ss-local-shared ss-redir-shared
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${RUNTIME_SHARED_OUTPUT_DIRECTORY}
        )

set_target_properties(shadowsocks-libev-shared PROPERTIES OUTPUT_NAME shadowsocks-libev)
set_target_properties(shadowsocks-libev-shared PROPERTIES VERSION 2.0.0 SOVERSION 2)
target_compile_definitions(shadowsocks-libev-shared PUBLIC -DMODULE_LOCAL)
target_link_libraries(shadowsocks-libev-shared ${DEPS_SHARED})

# ------------------------------------------------------------------
# Misc
# Recommend to install shared by default
install(DIRECTORY ${RUNTIME_SHARED_OUTPUT_DIRECTORY}/
        USE_SOURCE_PERMISSIONS
        DESTINATION ${CMAKE_INSTALL_BINDIR})

if (WITH_STATIC)
    install(TARGETS shadowsocks-libev
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif ()

install(TARGETS shadowsocks-libev-shared
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(FILES shadowsocks.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})


add_custom_target(distclean
        COMMAND ${CMAKE_COMMAND} -E echo WARNING: distclean target is not functional
        COMMAND ${CMAKE_COMMAND} -E echo Use 'git clean -fdx' instead
        VERBATIM
        )
