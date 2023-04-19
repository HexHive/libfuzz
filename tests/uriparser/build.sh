#!/bin/bash

CXX=$LLVM_DIR/bin/clang++

$CXX -std=c++11 -I/tmp/${TARGET}/work/include main.cc /tmp/uriparser/work/lib/liburiparser.a -o main