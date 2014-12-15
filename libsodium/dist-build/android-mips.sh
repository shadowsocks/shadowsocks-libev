#!/bin/sh
export CFLAGS="-Os"
TARGET_ARCH=mips HOST_COMPILER=mipsel-linux-android "$(dirname "$0")/android-build.sh"
