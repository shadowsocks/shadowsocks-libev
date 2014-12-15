#!/bin/sh
export CFLAGS="-Os -mthumb -marm -march=armv6"
TARGET_ARCH=arm HOST_COMPILER=arm-linux-androideabi "$(dirname "$0")/android-build.sh"
