dnl Check to find the zlib headers/libraries

AC_DEFUN([ss_ZLIB],
[
  AC_ARG_ENABLE([zlib],
    AS_HELP_STRING([--disable-zlib], [disable zlib compression support]))
  AS_IF([test "x$enable_zlib" != "xno"], [
  AC_DEFINE(HAVE_ZLIB, 1, [have zlib compression support])
    AC_ARG_WITH(zlib,
      AS_HELP_STRING([--with-zlib=DIR], [zlib base directory, or:]),
      [zlib="$withval"
       CPPFLAGS="$CPPFLAGS -I$withval/include"
       LDFLAGS="$LDFLAGS -L$withval/lib"]
    )

    AC_ARG_WITH(zlib-include,
      AS_HELP_STRING([--with-zlib-include=DIR], [zlib headers directory]),
      [zlib_include="$withval"
       CPPFLAGS="$CPPFLAGS -I$withval"]
    )

    AC_ARG_WITH(zlib-lib,
      AS_HELP_STRING([--with-zlib-lib=DIR], [zlib library directory]),
      [zlib_lib="$withval"
       LDFLAGS="$LDFLAGS -L$withval"]
    )

    AC_CHECK_HEADERS(zlib.h,
      [],
      [AC_MSG_ERROR("zlib header files not found."); break]
    )

    AC_CHECK_LIB(z, compress2,
      [LIBS="$LIBS -lz"],
      [AC_MSG_ERROR("zlib libraries not found.")]
    )
  ])
])
