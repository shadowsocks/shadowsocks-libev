# ===========================================================================
#     http://www.gnu.org/software/autoconf-archive/ax_check_gnu_make.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_CHECK_GNU_MAKE()
#
# DESCRIPTION
#
#   This macro searches for a GNU version of make. If a match is found, the
#   makefile variable `ifGNUmake' is set to the empty string, otherwise it
#   is set to "#". This is useful for including a special features in a
#   Makefile, which cannot be handled by other versions of make. The
#   variable _cv_gnu_make_command is set to the command to invoke GNU make
#   if it exists, the empty string otherwise.
#
#   Here is an example of its use:
#
#   Makefile.in might contain:
#
#     # A failsafe way of putting a dependency rule into a makefile
#     $(DEPEND):
#             $(CC) -MM $(srcdir)/*.c > $(DEPEND)
#
#     @ifGNUmake@ ifeq ($(DEPEND),$(wildcard $(DEPEND)))
#     @ifGNUmake@ include $(DEPEND)
#     @ifGNUmake@ endif
#
#   Then configure.in would normally contain:
#
#     AX_CHECK_GNU_MAKE()
#     AC_OUTPUT(Makefile)
#
#   Then perhaps to cause gnu make to override any other make, we could do
#   something like this (note that GNU make always looks for GNUmakefile
#   first):
#
#     if  ! test x$_cv_gnu_make_command = x ; then
#             mv Makefile GNUmakefile
#             echo .DEFAULT: > Makefile ;
#             echo \  $_cv_gnu_make_command \$@ >> Makefile;
#     fi
#
#   Then, if any (well almost any) other make is called, and GNU make also
#   exists, then the other make wraps the GNU make.
#
# LICENSE
#
#   Copyright (c) 2008 John Darrington <j.darrington@elvis.murdoch.edu.au>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 7

AC_DEFUN([AX_CHECK_GNU_MAKE], [ AC_CACHE_CHECK( for GNU make,_cv_gnu_make_command,
                _cv_gnu_make_command='' ;
dnl Search all the common names for GNU make
                for a in "$MAKE" make gmake gnumake ; do
                        if test -z "$a" ; then continue ; fi ;
                        if  ( sh -c "$a --version" 2> /dev/null | grep GNU  2>&1 > /dev/null ) ;  then
                                _cv_gnu_make_command=$a ;
                                break;
                        fi
                done ;
        ) ;
dnl If there was a GNU version, then set @ifGNUmake@ to the empty string, '#' otherwise
        if test  "x$_cv_gnu_make_command" != "x"  ; then
                ifGNUmake='' ;
        else
                ifGNUmake='#' ;
                AC_MSG_RESULT("Not found");
        fi
        AC_SUBST(ifGNUmake)
] )
