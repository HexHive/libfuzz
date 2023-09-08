#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##
git clone --no-checkout https://github.com/the-tcpdump-group/libpcap.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout bf8bfc74b2c8e893b2af2d657a5e53ae09dd7536
