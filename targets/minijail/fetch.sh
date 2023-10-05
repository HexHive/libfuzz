#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://chromium.googlesource.com/chromiumos/platform/minijail \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout 999a1c171d48ddf9a9e92da858c35fa46a40584e
