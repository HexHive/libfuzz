#!/bin/bash
set -x
set -e

. ./env.sh
# cmake .
export PATH=$LLVM_DIR/bin:$PATH
cmake -DCMAKE_BUILD_TYPE=Debug -DLLVM_INCLUDE_DIRS=/home/libfuzz/clang_13/include -DLLVM_DIR=$LLVM_DIR/lib . 
