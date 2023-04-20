#!/bin/bash

CXX=$LLVM_DIR/bin/clang++
CC=$LLVM_DIR/bin/clang

TARGET=uriparser
# TARGET=libtiff
DRIVER=driver0
DRIVER_FOLDER=/workspaces/libfuzz/workdir/${TARGET}/drivers

for d in `ls ${DRIVER_FOLDER}/${DRIVER}.cc`
do
    echo "Driver: $d"
    # echo "Output: ${d%%.*}"
    $CXX -g -std=c++11  -fsanitize=fuzzer,address -I/tmp/${TARGET}/work/include  $d /tmp/uriparser/work/lib/liburiparser.a -o "${d%%.*}"
    # $CXX -g -std=c++11  -fsanitize=fuzzer,address -I/tmp/${TARGET}/work/include  $d /tmp/${TARGET}/work/lib/libtiff.a /tmp/${TARGET}/work/lib/libtiffxx.a -lz -ljpeg -Wl,-Bstatic -llzma -Wl,-Bdynamic -lstdc++ -o "${d%%.*}"
done

