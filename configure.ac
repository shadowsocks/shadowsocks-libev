dnl                                               -*- Autoconf -*-
dnl Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([shadowsocks], [1.4.0], [max.c.lv@gmail.com])
AC_CONFIG_SRCDIR([src/encrypt.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign -Wall -Werror])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_LANG_SOURCE
AM_PROG_CC_C_O

dnl Checks for libev
m4_include([libev/libev.m4])

dnl Add library for mingw
case $host in
  *-mingw*)
    LIBS="$LIBS -lgdi32 -lws2_32"
    ;;
  *)
    ;;
esac

dnl Checks for openssl
ss_OPENSSL

dnl Checks for inet_ntop
ss_FUNC_INET_NTOP

dnl Checks for host.
AC_MSG_CHECKING(for what kind of host)
case $host in
  *-linux*)
    os_support=linux
    AC_MSG_RESULT(Linux)
    ;;
  *-mingw*)
    dnl Add custom macros for libev
    AC_DEFINE([FD_SETSIZE], [2048], [Reset max file descriptor size.])
    AC_DEFINE([EV_FD_TO_WIN32_HANDLE(fd)], [(fd)], [Override libev default fd conversion macro.])
    AC_DEFINE([EV_WIN32_HANDLE_TO_FD(handle)], [(handle)], [Override libev default handle conversion macro.])
    AC_DEFINE([EV_WIN32_CLOSE_FD(fd)], [closesocket(fd)], [Override libev default fd close macro.])

    os_support=mingw
    AC_MSG_RESULT(MinGW)
    ;;
  *)
    AC_MSG_RESULT(transparent proxy does not support for $host)
    ;;
esac

AM_CONDITIONAL(BUILD_REDIRECTOR, test "$os_support" = "linux")
AM_CONDITIONAL(BUILD_WINCOMPAT, test "$os_support" = "mingw")

dnl Checks for header files.
AC_CHECK_HEADERS([stdint.h inttypes.h arpa/inet.h fcntl.h langinfo.h locale.h netdb.h netinet/in.h stdlib.h string.h strings.h unistd.h sys/ioctl.h])

case $host in
  *-mingw*)
    AC_CHECK_HEADERS([windows.h winsock2.h ws2tcpip.h], [], [AC_MSG_ERROR([Missing MinGW headers])], [])
    ;;
  *)
    # These are POSIX-like systems using BSD-like sockets API.
    ;;
esac

dnl A special check required for <net/if.h> on Darwin. See
dnl http://www.gnu.org/software/autoconf/manual/html_node/Header-Portability.html.
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([net/if.h], [], [],
[
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
])

AC_C_BIGENDIAN

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SSIZE_T

dnl Checks for header files.
AC_HEADER_ASSERT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T
AC_HEADER_TIME

dnl Checks for library functions.
AC_FUNC_FORK
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([memset select setresuid setreuid strerror])

dnl Check for select() into ws2_32 for Msys/Mingw
if test "$ac_cv_func_select" != "yes"; then
  AC_MSG_CHECKING([for select in ws2_32])
  AC_TRY_LINK([
#ifdef HAVE_WINSOCK2_H
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#endif
    ],[
      select(0,(fd_set *)NULL,(fd_set *)NULL,(fd_set *)NULL,(struct timeval *)NULL);
    ],[
      AC_MSG_RESULT([yes])
      HAVE_SELECT="1"
      AC_DEFINE_UNQUOTED(HAVE_SELECT, 1,
        [Define to 1 if you have the `select' function.])
      HAVE_SYS_SELECT_H="1"
      AC_DEFINE_UNQUOTED(HAVE_SYS_SELECT_H, 1,
        [Define to 1 if you have the <sys/select.h> header file.])
    ],[
      AC_MSG_ERROR([no])
  ])
fi

AC_SYS_LARGEFILE

AC_CHECK_LIB(socket, connect)

dnl Checks for library functions.
AC_CHECK_FUNCS([malloc memset socket])

ACX_PTHREAD

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_FILES([Makefile
                 libasyncns/Makefile
                 libev/Makefile
                 src/Makefile])
AC_OUTPUT
