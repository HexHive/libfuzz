#!/bin/bash

FOLDER=/workspaces/libfuzz/analysis/openssl/repo/fuzz
for f in `ls $FOLDER`; do
    if [[ $f == *.c ]]; then
        grep "include" $FOLDER/$f; 
    fi
    # if grep -hR $f
done