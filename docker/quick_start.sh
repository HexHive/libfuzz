#!/bin/bash

export FUZZER=aflplusplus_lto_asan
# export PROGRAM=tiff_read_rgba_fuzzer
export PROGRAM=driver1
export TARGET=openssl
# export TARGET=libtiff  
export TIMEOUT=60
./build.sh
./run.sh