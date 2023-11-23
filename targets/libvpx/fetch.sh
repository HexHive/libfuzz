#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone https://chromium.googlesource.com/webm/libvpx \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout b8273e