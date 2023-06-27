#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone https://chromium.googlesource.com/webm/libvpx \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout d6eb9696aa72473c1a11d34d928d35a3acc0c9a9