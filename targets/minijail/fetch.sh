#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

git clone --no-checkout https://chromium.googlesource.com/chromiumos/platform/minijail \
    "$TARGET/repo"
git -C "$TARGET/repo" checkout ceb800091b03171c3998a57e37c25ac523c23b4d
