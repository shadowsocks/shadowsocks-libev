dnl Check to find the OpenSSL headers/libraries

AC_DEFUN([ss_OPENSSL],
[
  case $host_os in
    *mingw*)
    ;;
    *)
      AC_CHECK_FUNC(dlopen,
        [],
        [AC_CHECK_LIB(dl, dlopen,
          [LIBS="$LIBS -ldl"],
          [AC_MSG_ERROR([OpenSSL depends on libdl.]); break]
        )]
      )
    ;;
  esac

  AC_ARG_WITH(openssl,
    AS_HELP_STRING([--with-openssl=DIR], [OpenSSL base directory, or:]),
    [openssl="$withval"
     CFLAGS="$CFLAGS -I$withval/include"
     LDFLAGS="$LDFLAGS -L$withval/lib"]
  )

  AC_ARG_WITH(openssl-include,
    AS_HELP_STRING([--with-openssl-include=DIR], [OpenSSL headers directory (without trailing /openssl)]),
    [openssl_include="$withval"
     CFLAGS="$CFLAGS -I$withval"]
  )

  AC_ARG_WITH(openssl-lib,
    AS_HELP_STRING([--with-openssl-lib=DIR], [OpenSSL library directory]),
    [openssl_lib="$withval"
     LDFLAGS="$LDFLAGS -L$withval"]
  )

  AC_CHECK_HEADERS(openssl/evp.h openssl/rsa.h openssl/rand.h openssl/err.h openssl/sha.h openssl/pem.h openssl/engine.h,
    [],
    [AC_MSG_ERROR([OpenSSL header files not found.]); break]
  )

  AC_CHECK_LIB(crypto, EVP_EncryptInit_ex,
    [LIBS="-lcrypto $LIBS"],
    [AC_MSG_ERROR([OpenSSL libraries not found.])]
  )

  AC_CHECK_FUNCS([RAND_pseudo_bytes EVP_EncryptInit_ex], ,
    [AC_MSG_ERROR([Missing OpenSSL functionality, make sure you have installed the latest version.]); break],
  )

  AC_CHECK_DECL([OpenSSL_add_all_algorithms], ,
    [AC_MSG_ERROR([Missing OpenSSL functionality, make sure you have installed the latest version.]); break],
    [#include <openssl/evp.h>]
  )
])
