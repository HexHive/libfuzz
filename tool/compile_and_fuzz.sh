#!/bin/bash

CXX=$LLVM_DIR/bin/clang++
CC=$LLVM_DIR/bin/clang

TARGET=uriparser
# TARGET=libtiff
DRIVER=*
DRIVER_FOLDER=/workspaces/libfuzz/workdir/${TARGET}/drivers

for d in `ls ${DRIVER_FOLDER}/${DRIVER}.cc`
do
    echo "Driver: $d"
    # echo "Output: ${d%%.*}"
    $CXX -g -std=c++11  -fsanitize=fuzzer,address -I/tmp/uriparser/work/include  $d /tmp/libtiff/work/lib/libtiff.a /tmp/libtiff/work/lib/libtiffxx.a -lz -ljpeg -Wl,-Bstatic -llzma -Wl,-Bdynamic -lstdc++ -o "${d%%.*}"
    # $CXX -g -std=c++11  -fsanitize=fuzzer,address -I/tmp/libtiff/work/include  $d /tmp/libtiff/work/lib/libtiff.a /tmp/libtiff/work/lib/libtiffxx.a -lz -ljpeg -Wl,-Bstatic -llzma -Wl,-Bdynamic -lstdc++ -o "${d%%.*}"
done

