#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://github.com/OISF/libhtp.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 5aaea8cdc7ceac907b3cdbe265e8a2b5fe74d918