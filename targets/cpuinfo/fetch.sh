#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://android.googlesource.com/platform/external/cpuinfo \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 6ca2549f6b2ec107937292581826dbe810f75bfb
