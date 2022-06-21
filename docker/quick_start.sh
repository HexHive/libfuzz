#!/bin/bash

export FUZZER=aflplusplus_lto_asan
# export TARGET=openssl
export TARGET=libtiff  
export TIMEOUT=5
./build.sh
# ./run.sh