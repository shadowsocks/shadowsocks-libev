# FindPCRE.cmake - Find PCRE library
#
# Sets:
#   PCRE_FOUND
#   PCRE_INCLUDE_DIRS
#   PCRE_LIBRARIES

include(FindPkgConfig)

if(PKG_CONFIG_FOUND)
    pkg_check_modules(_PCRE QUIET libpcre)
endif()

if(_PCRE_FOUND)
    set(PCRE_INCLUDE_DIRS ${_PCRE_INCLUDE_DIRS})
    set(PCRE_LIBRARIES ${_PCRE_LIBRARIES})
    set(PCRE_FOUND TRUE)
else()
    # Try pcre-config
    find_program(PCRE_CONFIG pcre-config)
    if(PCRE_CONFIG)
        execute_process(COMMAND ${PCRE_CONFIG} --cflags
            OUTPUT_VARIABLE PCRE_CFLAGS
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        execute_process(COMMAND ${PCRE_CONFIG} --libs
            OUTPUT_VARIABLE PCRE_LDFLAGS
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        string(REGEX REPLACE "-I" "" PCRE_INCLUDE_DIRS "${PCRE_CFLAGS}")
        set(PCRE_LIBRARIES ${PCRE_LDFLAGS})
        set(PCRE_FOUND TRUE)
    else()
        # Manual search
        find_path(PCRE_INCLUDE_DIR
            NAMES pcre.h
            PATHS /usr/include /usr/local/include)
        if(NOT PCRE_INCLUDE_DIR)
            find_path(PCRE_INCLUDE_DIR
                NAMES pcre/pcre.h
                PATHS /usr/include /usr/local/include)
        endif()

        find_library(PCRE_LIBRARY
            NAMES pcre
            PATHS /usr/lib /usr/local/lib)

        if(PCRE_INCLUDE_DIR AND PCRE_LIBRARY)
            set(PCRE_INCLUDE_DIRS ${PCRE_INCLUDE_DIR})
            set(PCRE_LIBRARIES ${PCRE_LIBRARY})
            set(PCRE_FOUND TRUE)
        else()
            set(PCRE_FOUND FALSE)
        endif()
    endif()
endif()

if(PCRE_FOUND)
    message(STATUS "Found PCRE: ${PCRE_LIBRARIES}")
else()
    message(FATAL_ERROR "Could not find PCRE library. Install libpcre3-dev or equivalent.")
endif()
