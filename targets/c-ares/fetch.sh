#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##
git clone --no-checkout https://github.com/c-ares/c-ares.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 6360e96b5cf8e5980c887ce58ef727e53d77243a
