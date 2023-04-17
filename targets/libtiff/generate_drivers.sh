#!/bin/bash



${LIBFUZZ}/tool/main.py \
    --config ${TARGET}/generator.toml \
    --overwrite ${LIBFUZZ}/overwrite.toml
