# FindPCRE2.cmake - Find PCRE2 library (8-bit)
#
# Sets:
#   PCRE2_FOUND
#   PCRE2_INCLUDE_DIRS
#   PCRE2_LIBRARIES

include(FindPkgConfig)

if(PKG_CONFIG_FOUND)
    pkg_check_modules(_PCRE2 QUIET libpcre2-8)
endif()

if(_PCRE2_FOUND)
    set(PCRE2_INCLUDE_DIRS ${_PCRE2_INCLUDE_DIRS})
    set(PCRE2_LIBRARIES ${_PCRE2_LIBRARIES})
    set(PCRE2_FOUND TRUE)
else()
    # Try pcre2-config
    find_program(PCRE2_CONFIG pcre2-config)
    if(PCRE2_CONFIG)
        execute_process(COMMAND ${PCRE2_CONFIG} --cflags
            OUTPUT_VARIABLE PCRE2_CFLAGS
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        execute_process(COMMAND ${PCRE2_CONFIG} --libs8
            OUTPUT_VARIABLE PCRE2_LDFLAGS
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        string(REGEX REPLACE "-I" "" PCRE2_INCLUDE_DIRS "${PCRE2_CFLAGS}")
        set(PCRE2_LIBRARIES ${PCRE2_LDFLAGS})
        set(PCRE2_FOUND TRUE)
    else()
        # Manual search
        find_path(PCRE2_INCLUDE_DIR
            NAMES pcre2.h
            HINTS
                /opt/homebrew/include
                /usr/local/include
                /usr/include
        )

        find_library(PCRE2_LIBRARY
            NAMES pcre2-8
            HINTS
                /opt/homebrew/lib
                /usr/local/lib
                /usr/lib
        )

        if(PCRE2_INCLUDE_DIR AND PCRE2_LIBRARY)
            set(PCRE2_INCLUDE_DIRS ${PCRE2_INCLUDE_DIR})
            set(PCRE2_LIBRARIES ${PCRE2_LIBRARY})
            set(PCRE2_FOUND TRUE)
        else()
            set(PCRE2_FOUND FALSE)
        endif()
    endif()
endif()

if(PCRE2_FOUND)
    message(STATUS "Found PCRE2: ${PCRE2_LIBRARIES}")
else()
    message(FATAL_ERROR "Could not find PCRE2 library. Install libpcre2-dev or equivalent.")
endif()
