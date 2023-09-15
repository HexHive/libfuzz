#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone https://chromium.googlesource.com/webm/libvpx \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 8f8e7414684e97ea9b94710ac7853565c8a11c3a