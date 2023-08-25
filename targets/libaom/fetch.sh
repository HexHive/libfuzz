#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##
git clone --no-checkout https://aomedia.googlesource.com/aom \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout ab8fddcfc19b54d2a2243dd8a396f4ea3c19b188
