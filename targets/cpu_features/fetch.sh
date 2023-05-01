#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://android.googlesource.com/platform/external/cpu_features \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 99eb6aeb118b624ccf0c3ba371c806462b9f9519