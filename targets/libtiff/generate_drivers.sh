#!/bin/bash



${LIBFUZZ}/tool/main.py \
    --config ${LIBFUZZ}/targets/${TARGET_NAME}/generator.toml \
    --overwrite ${LIBFUZZ}/general.toml
