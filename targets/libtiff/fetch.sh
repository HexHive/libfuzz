#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://gitlab.com/libtiff/libtiff.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 4d0329a4539550f2396772b8c4c60c5fecdda7db