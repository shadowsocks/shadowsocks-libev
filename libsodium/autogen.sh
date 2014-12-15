#! /bin/sh

if [ -x "`which autoreconf 2>/dev/null`" ] ; then
  exec autoreconf -ivf
fi

if glibtoolize --version > /dev/null 2>&1; then
  LIBTOOLIZE='glibtoolize'
else
  LIBTOOLIZE='libtoolize'
fi

$LIBTOOLIZE && \
aclocal && \
automake --add-missing --force-missing --include-deps && \
autoconf
