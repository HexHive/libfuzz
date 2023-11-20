#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://github.com/madler/zlib  \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 09155eaa2f9270dc4ed1fa13e2b4b2613e6e4851
