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

# Helper function to add a unit test
function(ss_add_test name sources libs)
    add_executable(${name} ${sources})
    target_compile_definitions(${name} PRIVATE -DHAVE_CONFIG_H)
    target_link_libraries(${name} ${libs})
    add_test(NAME ${name} COMMAND ${name})
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

# test_netutils - needs cork for ip address parsing
set(TEST_NETUTILS_LIBS
    ${LIBSODIUM_SHARED}
    ${LIBEV_SHARED}
    ${LIBUDNS_SHARED}
)
if(WITH_EMBEDDED_SRC)
    list(APPEND TEST_NETUTILS_LIBS cork-shared)
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
    list(APPEND TEST_PPBLOOM_LIBS bloom-shared)
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
    list(APPEND TEST_RULE_LIBS cork-shared)
else()
    list(APPEND TEST_RULE_LIBS ${LIBCORK_SHARED})
endif()
ss_add_test(test_rule
    "test_rule.c;${PROJECT_SOURCE_DIR}/src/rule.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "${TEST_RULE_LIBS}")

# test_jconf - needs cork and json
set(TEST_JCONF_LIBS
    ${LIBSODIUM_SHARED}
    ${LIBEV_SHARED}
    ${LIBUDNS_SHARED}
)
if(WITH_EMBEDDED_SRC)
    list(APPEND TEST_JCONF_LIBS cork-shared)
else()
    list(APPEND TEST_JCONF_LIBS ${LIBCORK_SHARED})
endif()
ss_add_test(test_jconf
    "test_jconf.c;${PROJECT_SOURCE_DIR}/src/jconf.c;${PROJECT_SOURCE_DIR}/src/json.c;${PROJECT_SOURCE_DIR}/src/utils.c;${PROJECT_SOURCE_DIR}/src/netutils.c"
    "${TEST_JCONF_LIBS};m")

# test_buffer - needs sodium and mbedtls for crypto.c buffer functions
ss_add_test(test_buffer
    "test_buffer.c;${PROJECT_SOURCE_DIR}/src/crypto.c;${PROJECT_SOURCE_DIR}/src/utils.c;${PROJECT_SOURCE_DIR}/src/base64.c;${PROJECT_SOURCE_DIR}/src/aead.c;${PROJECT_SOURCE_DIR}/src/stream.c;${PROJECT_SOURCE_DIR}/src/ppbloom.c;${PROJECT_SOURCE_DIR}/src/cache.c"
    "${LIBSODIUM_SHARED};${LIBMBEDTLS_SHARED};${LIBMBEDCRYPTO_SHARED};${LIBEV_SHARED};${TEST_PPBLOOM_LIBS};m")

# test_crypto - full crypto test
set(TEST_CRYPTO_LIBS
    ${LIBSODIUM_SHARED}
    ${LIBMBEDTLS_SHARED}
    ${LIBMBEDCRYPTO_SHARED}
    ${LIBEV_SHARED}
)
if(WITH_EMBEDDED_SRC)
    list(APPEND TEST_CRYPTO_LIBS bloom-shared)
else()
    list(APPEND TEST_CRYPTO_LIBS ${LIBBLOOM_SHARED})
endif()
ss_add_test(test_crypto
    "test_crypto.c;${PROJECT_SOURCE_DIR}/src/crypto.c;${PROJECT_SOURCE_DIR}/src/aead.c;${PROJECT_SOURCE_DIR}/src/stream.c;${PROJECT_SOURCE_DIR}/src/ppbloom.c;${PROJECT_SOURCE_DIR}/src/cache.c;${PROJECT_SOURCE_DIR}/src/base64.c;${PROJECT_SOURCE_DIR}/src/utils.c"
    "${TEST_CRYPTO_LIBS};m")

# test_ss_setup - bash unit tests for the ss-setup TUI tool
add_test(NAME test_ss_setup
    COMMAND bash "${PROJECT_SOURCE_DIR}/tests/test_ss_setup.sh"
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
