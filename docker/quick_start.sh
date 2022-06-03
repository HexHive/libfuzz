#!/bin/bash

export FUZZER=aflplusplus_lto_asan
# export PROGRAM=tiff_read_rgba_fuzzer
export PROGRAM=driver0
# export TARGET=openssl
export TARGET=libtiff  
export TIMEOUT=5
./build.sh
./run.sh