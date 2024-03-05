#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://android.googlesource.com/platform/external/pthreadpool \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 820ff0d95f4937c953951aae273a72b0980dd7eb