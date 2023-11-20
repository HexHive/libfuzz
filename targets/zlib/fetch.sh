#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://github.com/madler/zlib  \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 643e17b7498d12ab8d15565662880579692f769d
