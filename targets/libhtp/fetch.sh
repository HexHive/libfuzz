#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://github.com/OISF/libhtp.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 8bdfe7b9d04e5e948c8fbaa7472e14d884cc00af