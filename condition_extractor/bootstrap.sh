#!/bin/bash
set -x
set -e

. ./env.sh
# cmake .
export PATH=$LLVM_DIR/bin:$PATH
cmake -DCMAKE_BUILD_TYPE=Debug . 
