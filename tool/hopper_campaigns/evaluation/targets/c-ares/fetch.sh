#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##
git clone --no-checkout https://github.com/c-ares/c-ares.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 7f3262312f246556d8c1bdd8ccc1844847f42787
