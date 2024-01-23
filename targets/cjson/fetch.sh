#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##
git clone --no-checkout https://github.com/DaveGamble/cJSON.git \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 87d8f0961a01bf09bef98ff89bae9fdec42181ee
