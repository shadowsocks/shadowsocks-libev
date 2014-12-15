#!/bin/sh
export CFLAGS="-Os -mfloat-abi=softfp -mfpu=vfpv3-d16 -mthumb -marm -march=armv7-a"
TARGET_ARCH=armv7 HOST_COMPILER=arm-linux-androideabi "$(dirname "$0")/android-build.sh"
