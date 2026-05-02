# FindMbedTLS.cmake - Find mbedTLS library with feature detection
#
# Sets:
#   MBEDTLS_FOUND
#   MBEDTLS_INCLUDE_DIRS
#   MBEDTLS_CRYPTO_LIBRARY
#   MBEDTLS_TLS_LIBRARY

include(CheckCSourceCompiles)

# mbedtls@3 is keg-only on Homebrew; also check versioned opt paths
find_path(MBEDTLS_INCLUDE_DIR
    NAMES mbedtls/cipher.h
    HINTS
        /opt/homebrew/opt/mbedtls@3/include
        /usr/local/opt/mbedtls@3/include
        /opt/homebrew/opt/mbedtls/include
        /usr/local/opt/mbedtls/include
        /opt/homebrew/include
        /usr/local/include
        /usr/include
)

find_library(MBEDTLS_CRYPTO_LIBRARY
    NAMES mbedcrypto
    HINTS
        /opt/homebrew/opt/mbedtls@3/lib
        /usr/local/opt/mbedtls@3/lib
        /opt/homebrew/opt/mbedtls/lib
        /usr/local/opt/mbedtls/lib
        /opt/homebrew/lib
        /usr/local/lib
        /usr/lib
)

find_library(MBEDTLS_TLS_LIBRARY
    NAMES mbedtls
    HINTS
        /opt/homebrew/opt/mbedtls@3/lib
        /usr/local/opt/mbedtls@3/lib
        /opt/homebrew/opt/mbedtls/lib
        /usr/local/opt/mbedtls/lib
        /opt/homebrew/lib
        /usr/local/lib
        /usr/lib
)

if(MBEDTLS_INCLUDE_DIR AND MBEDTLS_CRYPTO_LIBRARY)
    set(MBEDTLS_FOUND TRUE)
    set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})

    # Check for required CFB mode support
    set(CMAKE_REQUIRED_INCLUDES ${MBEDTLS_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${MBEDTLS_CRYPTO_LIBRARY})

    check_c_source_compiles("
        #include <mbedtls/cipher.h>
        #if !defined(MBEDTLS_CIPHER_MODE_CFB)
        #error CFB mode not supported
        #endif
        int main(void) { return 0; }
    " MBEDTLS_HAS_CFB)

    if(NOT MBEDTLS_HAS_CFB)
        # Try mbedtls 3.x config path
        check_c_source_compiles("
            #include <mbedtls/build_info.h>
            #include <mbedtls/cipher.h>
            #if !defined(MBEDTLS_CIPHER_MODE_CFB)
            #error CFB mode not supported
            #endif
            int main(void) { return 0; }
        " MBEDTLS_HAS_CFB_V3)

        if(NOT MBEDTLS_HAS_CFB_V3)
            message(FATAL_ERROR "mbedTLS found but MBEDTLS_CIPHER_MODE_CFB is not enabled. "
                "Please enable CFB mode in your mbedTLS configuration.")
        endif()
    endif()

    unset(CMAKE_REQUIRED_INCLUDES)
    unset(CMAKE_REQUIRED_LIBRARIES)

    message(STATUS "Found mbedTLS: ${MBEDTLS_CRYPTO_LIBRARY}")
else()
    set(MBEDTLS_FOUND FALSE)
    message(FATAL_ERROR "Could not find mbedTLS library. Install libmbedtls-dev or equivalent.")
endif()
