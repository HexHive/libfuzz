#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##
git clone --no-checkout https://github.com/the-tcpdump-group/libpcap.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 7d92092c7f6b4bcd36c192aae68b8663bce831a0
