# Unit tests using CTest
include_directories(BEFORE ${MBEDTLS_INCLUDE_DIRS})
include_directories(${PROJECT_SOURCE_DIR}/src)
include_directories(${PROJECT_BINARY_DIR}/src)
include_directories(${SODIUM_INCLUDE_DIRS})
include_directories(${PCRE2_INCLUDE_DIRS})
include_directories(${CARES_INCLUDE_DIRS})

if(WITH_EMBEDDED_SRC)
    include_directories(${PROJECT_SOURCE_DIR}/libcork/include)
    include_directories(${PROJECT_SOURCE_DIR}/libipset/include)
    include_directories(${PROJECT_SOURCE_DIR}/libbloom/murmur2)
    include_directories(${PROJECT_SOURCE_DIR}/libbloom)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_program(VALGRIND_EXECUTABLE NAMES valgrind)
endif()

# Helper function to add a unit test
function(ss_add_test name sources libs)
    add_executable(${name} ${sources})
    target_compile_definitions(${name} PRIVATE -DHAVE_CONFIG_H)
    target_link_libraries(${name} ${libs})
    # Keep assertions enabled for tests even in Release builds.
    target_compile_options(${name} PRIVATE -UNDEBUG)
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES LABELS "unit")

    if(VALGRIND_EXECUTABLE)
        add_test(NAME memcheck_${name}
            COMMAND ${VALGRIND_EXECUTABLE}
                --tool=memcheck
                --leak-check=full
                --show-leak-kinds=definite,indirect
                --errors-for-leak-kinds=definite,indirect
                --error-exitcode=1
                --track-origins=yes
                --quiet
                $<TARGET_FILE:${name}>)
        set_tests_properties(memcheck_${name}
            PROPERTIES
                LABELS "memcheck"
                TIMEOUT 120)
    endif()
endfunction()

# test_base64 - no external deps
ss_add_test(test_base64
    "test_base64.c;${PROJECT_SOURCE_DIR}/src/base64.c"
    "")

# test_utils - needs sodium (for ss_malloc -> uses sodium in utils.c)
ss_add_test(test_utils
    "test_utils.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "${LIBSODIUM_SHARED}")

# test_json - standalone json parser
ss_add_test(test_json
    "test_json.c;${PROJECT_SOURCE_DIR}/src/json.c"
    "m")

# test_ssurl - ss:// URI parsing (SIP002 and legacy)
ss_add_test(test_ssurl
    "test_ssurl.c;${PROJECT_SOURCE_DIR}/src/ssurl.c;${PROJECT_SOURCE_DIR}/src/base64.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "${LIBSODIUM_SHARED}")

# test_netutils - needs cork for ip address parsing
set(TEST_NETUTILS_LIBS
    ${LIBSODIUM_SHARED}
    ${LIBEV_SHARED}
    ${LIBUDNS_SHARED}
)
if(WITH_EMBEDDED_SRC)
    list(APPEND TEST_NETUTILS_LIBS cork)
else()
    list(APPEND TEST_NETUTILS_LIBS ${LIBCORK_SHARED})
endif()
ss_add_test(test_netutils
    "test_netutils.c;${PROJECT_SOURCE_DIR}/src/netutils.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "${TEST_NETUTILS_LIBS}")

# test_cache - needs libev for ev_time()
ss_add_test(test_cache
    "test_cache.c;${PROJECT_SOURCE_DIR}/src/cache.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "${LIBEV_SHARED};${LIBSODIUM_SHARED}")

# test_ppbloom - needs bloom
set(TEST_PPBLOOM_LIBS "")
if(WITH_EMBEDDED_SRC)
    list(APPEND TEST_PPBLOOM_LIBS bloom)
else()
    list(APPEND TEST_PPBLOOM_LIBS ${LIBBLOOM_SHARED})
endif()
ss_add_test(test_ppbloom
    "test_ppbloom.c;${PROJECT_SOURCE_DIR}/src/ppbloom.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "${TEST_PPBLOOM_LIBS};${LIBSODIUM_SHARED};m")

# test_rule - needs pcre and cork
set(TEST_RULE_LIBS
    ${LIBPCRE2_SHARED}
    ${LIBSODIUM_SHARED}
)
if(WITH_EMBEDDED_SRC)
    list(APPEND TEST_RULE_LIBS cork)
else()
    list(APPEND TEST_RULE_LIBS ${LIBCORK_SHARED})
endif()
ss_add_test(test_rule
    "test_rule.c;${PROJECT_SOURCE_DIR}/src/rule.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "${TEST_RULE_LIBS}")

# test_acl - needs pcre, cork, and ipset
set(TEST_ACL_LIBS ${TEST_RULE_LIBS})
if(WITH_EMBEDDED_SRC)
    list(APPEND TEST_ACL_LIBS ipset)
else()
    list(APPEND TEST_ACL_LIBS ${LIBCORKIPSET_SHARED})
endif()
ss_add_test(test_acl
    "test_acl.c;${PROJECT_SOURCE_DIR}/src/acl.c;${PROJECT_SOURCE_DIR}/src/rule.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "${TEST_ACL_LIBS}")

# test_jconf - needs cork and json
set(TEST_JCONF_LIBS
    ${LIBSODIUM_SHARED}
    ${LIBEV_SHARED}
    ${LIBUDNS_SHARED}
)
if(WITH_EMBEDDED_SRC)
    list(APPEND TEST_JCONF_LIBS cork)
else()
    list(APPEND TEST_JCONF_LIBS ${LIBCORK_SHARED})
endif()
ss_add_test(test_jconf
    "test_jconf.c;${PROJECT_SOURCE_DIR}/src/jconf.c;${PROJECT_SOURCE_DIR}/src/json.c;${PROJECT_SOURCE_DIR}/src/utils.c;${PROJECT_SOURCE_DIR}/src/netutils.c"
    "${TEST_JCONF_LIBS};m")

# Crypto sources shared by the tests that link the crypto layer. The AEAD-2022
# ciphers pull in BLAKE3 (linked as the `blake3` target) and the session-based
# UDP codec, so they must be built together with crypto.c.
set(SS_CRYPTO_TEST_SOURCES
    ${PROJECT_SOURCE_DIR}/src/crypto.c
    ${PROJECT_SOURCE_DIR}/src/aead.c
    ${PROJECT_SOURCE_DIR}/src/aead2022.c
    ${PROJECT_SOURCE_DIR}/src/aead2022_udp.c
    ${PROJECT_SOURCE_DIR}/src/stream.c
    ${PROJECT_SOURCE_DIR}/src/ppbloom.c
    ${PROJECT_SOURCE_DIR}/src/cache.c
    ${PROJECT_SOURCE_DIR}/src/base64.c
    ${PROJECT_SOURCE_DIR}/src/utils.c
)

# test_buffer - needs sodium and mbedtls for crypto.c buffer functions
ss_add_test(test_buffer
    "test_buffer.c;${SS_CRYPTO_TEST_SOURCES}"
    "${LIBSODIUM_SHARED};${LIBMBEDTLS_SHARED};${LIBMBEDCRYPTO_SHARED};${LIBEV_SHARED};${TEST_PPBLOOM_LIBS};blake3;m")

# test_crypto - full crypto test
set(TEST_CRYPTO_LIBS
    ${LIBSODIUM_SHARED}
    ${LIBMBEDTLS_SHARED}
    ${LIBMBEDCRYPTO_SHARED}
    ${LIBEV_SHARED}
)
if(WITH_EMBEDDED_SRC)
    list(APPEND TEST_CRYPTO_LIBS bloom)
else()
    list(APPEND TEST_CRYPTO_LIBS ${LIBBLOOM_SHARED})
endif()
# BLAKE3 backs the 2022 ciphers' key derivation
list(APPEND TEST_CRYPTO_LIBS blake3)
ss_add_test(test_crypto
    "test_crypto.c;${SS_CRYPTO_TEST_SOURCES}"
    "${TEST_CRYPTO_LIBS};m")

# test_aead2022 - Shadowsocks 2022 Edition (SIP022) ciphers
ss_add_test(test_aead2022
    "test_aead2022.c;${SS_CRYPTO_TEST_SOURCES}"
    "${TEST_CRYPTO_LIBS};m")

# test_interop_rust - interoperability against shadowsocks-rust.
# Skips itself when shadowsocks-rust or the built binaries are absent.
add_test(NAME test_interop_rust
    COMMAND bash "${PROJECT_SOURCE_DIR}/tests/test_interop_rust.sh"
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
set_tests_properties(test_interop_rust PROPERTIES
    LABELS "integration"
    TIMEOUT 300
    ENVIRONMENT "SS_BIN_DIR=${RUNTIME_SHARED_OUTPUT_DIRECTORY}")

# test_ss_setup - bash unit tests for the ss-setup TUI tool
add_test(NAME test_ss_setup
    COMMAND bash "${PROJECT_SOURCE_DIR}/tests/test_ss_setup.sh"
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
set_tests_properties(test_ss_setup PROPERTIES LABELS "integration")
