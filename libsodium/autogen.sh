#! /bin/sh

if glibtoolize --version > /dev/null 2>&1; then
  LIBTOOLIZE='glibtoolize'
else
  LIBTOOLIZE='libtoolize'
fi

if [ ! -x "`which $LIBTOOLIZE 2>/dev/null`" ] ; then
  echo "libtool is required, but wasn't found on this system"
  exit 1
fi

if [ ! -x "`which autoconf 2>/dev/null`" ] ; then
  echo "autoconf is required, but wasn't found on this system"
  exit 1
fi

if [ ! -x "`which automake 2>/dev/null`" ] ; then
  echo "automake is required, but wasn't found on this system"
  exit 1
fi

if [ ! -x "`which pkg-config 2>/dev/null`" ] ; then
  echo "pkg-config is required, but wasn't found on this system"
  exit 1
fi

if [ -x "`which autoreconf 2>/dev/null`" ] ; then
  exec autoreconf -ivf
fi

$LIBTOOLIZE && \
aclocal && \
automake --add-missing --force-missing --include-deps && \
autoconf
