#!/bin/sh
export CFLAGS="-Os"
TARGET_ARCH=x86 HOST_COMPILER=i686-linux-android "$(dirname "$0")/android-build.sh"
