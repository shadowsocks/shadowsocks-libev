#! /bin/sh

export XCODEDIR=$(xcode-select -p)
export BASEDIR="${XCODEDIR}/Platforms/iPhoneOS.platform/Developer"
export PATH="${BASEDIR}/usr/bin:$BASEDIR/usr/sbin:$PATH"
export SDK="${BASEDIR}/SDKs/iPhoneOS.sdk"
export IPHONEOS_VERSION_MIN="5.1.1"
export CFLAGS="-Oz -mthumb -arch armv7 -isysroot ${SDK} -miphoneos-version-min=${IPHONEOS_VERSION_MIN}"
export LDFLAGS="-mthumb -arch armv7 -isysroot ${SDK} -miphoneos-version-min=${IPHONEOS_VERSION_MIN}"
export PREFIX="$(pwd)/libsodium-ios"

./configure --host=arm-apple-darwin10 \
            --disable-shared \
            --enable-minimal \
            --prefix="$PREFIX" && \
make clean && \
make -j3 install && \
echo "libsodium has been installed into $PREFIX"
