#! /bin/sh

export CFLAGS="-O3 -fomit-frame-pointer -m64 -mtune=nocona"
export PREFIX="$(pwd)/libsodium-win64"

./configure --prefix="$PREFIX" --exec-prefix="$PREFIX" \
            --host=x86_64-w64-mingw32 && \
make && \
make check && \
make install
