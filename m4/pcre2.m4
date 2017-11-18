dnl -------------------------------------------------------- -*- autoconf -*-
dnl Licensed to the Apache Software Foundation (ASF) under one or more
dnl contributor license agreements.  See the NOTICE file distributed with
dnl this work for additional information regarding copyright ownership.
dnl The ASF licenses this file to You under the Apache License, Version 2.0
dnl (the "License"); you may not use this file except in compliance with
dnl the License.  You may obtain a copy of the License at
dnl
dnl     http://www.apache.org/licenses/LICENSE-2.0
dnl
dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl See the License for the specific language governing permissions and
dnl limitations under the License.

dnl Modified by Syrone Wong <wong.syrone@gmail.com> to support pcre2 8bit variant only

dnl
dnl TS_ADDTO(variable, value)
dnl
dnl  Add value to variable
dnl
AC_DEFUN([TS_ADDTO], [
  if test "x$$1" = "x"; then
    test "x$verbose" = "xyes" && echo "  setting $1 to \"$2\""
    $1="$2"
  else
    ats_addto_bugger="$2"
    for i in $ats_addto_bugger; do
      ats_addto_duplicate="0"
      for j in $$1; do
        if test "x$i" = "x$j"; then
          ats_addto_duplicate="1"
          break
        fi
      done
      if test $ats_addto_duplicate = "0"; then
        test "x$verbose" = "xyes" && echo "  adding \"$i\" to $1"
        $1="$$1 $i"
      fi
    done
  fi
])dnl

dnl
dnl TS_ADDTO_RPATH(path)
dnl
dnl   Adds path to variable with the '-rpath' directive.
dnl
AC_DEFUN([TS_ADDTO_RPATH], [
  AC_MSG_NOTICE([adding $1 to RPATH])
  TS_ADDTO(LIBTOOL_LINK_FLAGS, [-R$1])
])dnl

dnl
dnl pcre2.m4: Trafficserver's pcre2 autoconf macros
dnl

dnl
dnl TS_CHECK_PCRE2: look for pcre2 libraries and headers
dnl
AC_DEFUN([TS_CHECK_PCRE2], [
enable_pcre2=no
AC_ARG_WITH(pcre2, [AC_HELP_STRING([--with-pcre2=DIR],[use a specific pcre2 library])],
[
  if test "x$withval" != "xyes" && test "x$withval" != "x"; then
    pcre2_base_dir="$withval"
    if test "$withval" != "no"; then
      enable_pcre2=yes
      case "$withval" in
      *":"*)
        pcre2_include="`echo $withval |sed -e 's/:.*$//'`"
        pcre2_ldflags="`echo $withval |sed -e 's/^.*://'`"
        AC_MSG_CHECKING(checking for pcre2 includes in $pcre2_include libs in $pcre2_ldflags )
        ;;
      *)
        pcre2_include="$withval/include"
        pcre2_ldflags="$withval/lib"
        AC_MSG_CHECKING(checking for pcre2 includes in $withval)
        ;;
      esac
    fi
  fi
],
[
  AC_CHECK_PROG(PCRE2_CONFIG, pcre2-config, pcre2-config)
  if test "x$PCRE2_CONFIG" != "x"; then
    enable_pcre2=yes
    pcre2_base_dir="`$PCRE2_CONFIG --prefix`"
    pcre2_include="`$PCRE2_CONFIG --cflags | sed -es/-I//`"
    pcre2_ldflags="`$PCRE2_CONFIG --libs8 | sed -es/-lpcre2-8// -es/-L//`"
  fi
])

if test "x$pcre2_base_dir" = "x"; then
  AC_MSG_CHECKING([for pcre2 location])
  AC_CACHE_VAL(ats_cv_pcre2_dir,[
  for dir in /usr/local /usr ; do
    if test -d $dir && ( test -f $dir/include/pcre2.h || test -f $dir/include/pcre2/pcre2.h ); then
      ats_cv_pcre2_dir=$dir
      break
    fi
  done
  ])
  pcre2_base_dir=$ats_cv_pcre2_dir
  if test "x$pcre2_base_dir" = "x"; then
    enable_pcre2=no
    AC_MSG_RESULT([not found])
  else
    enable_pcre2=yes
    pcre2_include="$pcre2_base_dir/include"
    pcre2_ldflags="$pcre2_base_dir/lib"
    AC_MSG_RESULT([$pcre2_base_dir])
  fi
else
  AC_MSG_CHECKING(for pcre2 headers in $pcre2_include)
  if test -d $pcre2_include && test -d $pcre2_ldflags && ( test -f $pcre2_include/pcre2.h || test -f $pcre2_include/pcre2/pcre2.h ); then
    AC_MSG_RESULT([ok])
  else
    AC_MSG_RESULT([not found])
  fi
fi

pcre2h=0
pcre2_pcre2h=0
if test "$enable_pcre2" != "no"; then
  saved_ldflags=$LDFLAGS
  saved_cppflags=$CFLAGS
  pcre2_have_headers=0
  pcre2_have_libs=0
  if test "$pcre2_base_dir" != "/usr"; then
    TS_ADDTO(CFLAGS, [-I${pcre2_include}])
    TS_ADDTO(CFLAGS, [-DPCRE2_STATIC])
    TS_ADDTO(LDFLAGS, [-L${pcre2_ldflags}])
    TS_ADDTO_RPATH(${pcre2_ldflags})
  fi
  AC_SEARCH_LIBS([pcre2_match_8], [pcre2-8], [pcre2_have_libs=1])
  if test "$pcre2_have_libs" != "0"; then
      AC_MSG_CHECKING([pcre2.h])
  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
      [[
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
      ]],
      [[
      ]]
    )],
    [pcre2_have_headers=1
    AC_MSG_RESULT([ok])],
    [AC_MSG_RESULT([not found])]
  )

    AC_MSG_CHECKING([pcre2/pcre2.h])
  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
      [[
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2/pcre2.h>
      ]],
      [[
      ]]
    )],
    [pcre2_have_headers=1
    AC_MSG_RESULT([ok])],
    [AC_MSG_RESULT([not found])]
  )
  fi
  if test "$pcre2_have_headers" != "0"; then
    AC_DEFINE(HAVE_LIBPCRE2,1,[Compiling with pcre2 support])
    AC_SUBST(LIBPCRE2, [-lpcre2-8])
  else
    enable_pcre2=no
    CFLAGS=$saved_cppflags
    LDFLAGS=$saved_ldflags
  fi
fi
AC_SUBST(pcre2h)
AC_SUBST(pcre2_pcre2h)
])
