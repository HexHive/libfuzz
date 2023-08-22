#!/bin/bash

set -e
set -x

# NOTE: if TOOLD_DIR is unset, I assume to find stuffs in LIBFUZZ folder
if [ -z "$TOOLS_DIR" ]; then
    TOOLS_DIR=$LIBFUZZ
fi

WORK="$TARGET/work"
rm -rf "$WORK"
mkdir -p "$WORK"
mkdir -p "$WORK/lib" "$WORK/include"

export CC=wllvm
export CXX=wllvm++
export LLVM_COMPILER=clang
echo "$LLVM_DIR"
export LLVM_COMPILER_PATH=$LLVM_DIR/bin



echo "make 1"
mkdir -p "$TARGET/repo/aom_build"
cd "$TARGET/repo/aom_build"


cmake .. -DCMAKE_INSTALL_PREFIX="$WORK" -DBUILD_SHARED_LIBS=off \
        -DENABLE_STATIC=on -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS_DEBUG="-g -O0" \
        -DCMAKE_CXX_FLAGS_DEBUG="-g -O0"
# configure compiles some shits for testing, better remove it
echo "[INFO] Library installed in: $WORK"
