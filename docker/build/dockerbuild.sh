#!/bin/sh
set -e
set -o xtrace

cmake -DBUILD_STATIC=OFF . && make && make install