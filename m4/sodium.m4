dnl Check to find the libsodium headers/libraries

AC_DEFUN([ss_SODIUM],
[

    AC_ARG_WITH(sodium,
    AS_HELP_STRING([--with-sodium=DIR], [The Sodium crypto library base directory, or:]),
    [sodium="$withval"
     CFLAGS="$CFLAGS -I$withval/include"
     LDFLAGS="$LDFLAGS -L$withval/lib"]
    )

    AC_ARG_WITH(sodium-include,
    AS_HELP_STRING([--with-sodium-include=DIR], [The Sodium crypto library headers directory (without trailing /sodium)]),
    [sodium_include="$withval"
     CFLAGS="$CFLAGS -I$withval"]
    )

    AC_ARG_WITH(sodium-lib,
    AS_HELP_STRING([--with-sodium-lib=DIR], [The Sodium crypto library library directory]),
    [sodium_lib="$withval"
     LDFLAGS="$LDFLAGS -L$withval"]
    )

    AC_CHECK_LIB(sodium, sodium_init,
    [LIBS="-lsodium $LIBS"],
    [AC_MSG_ERROR([The Sodium crypto library libraries not found.])]
    )

])
