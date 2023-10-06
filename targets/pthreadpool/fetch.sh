#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://android.googlesource.com/platform/external/pthreadpool \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout bf08f8656c6cb12f73122b1aacc16726cbf8d6ce