#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##
git clone --no-checkout https://aomedia.googlesource.com/aom \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout f7c32d8ba9c1d9406196b1c80b70d33fb0d2d3ea
