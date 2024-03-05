#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://android.googlesource.com/platform/external/cpu_features \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 925e059f65798dab125ec08bea999308cf00c86e