#!/bin/bash

# CXX=$LLVM_DIR/bin/clang++
# CC=$LLVM_DIR/bin/clang

for d in `ls ${TARGET}/drivers/`
do
    echo "Driver: $d"
    # $CXX -g -std=c++11  -fsanitize=fuzzer,address -I/tmp/libtiff/work/include  ./workdir/drivers/driver$i.cc /tmp/libtiff/work/lib/libtiff.a /tmp/libtiff/work/lib/libtiffxx.a -lz -ljpeg -Wl,-Bstatic -llzma -Wl,-Bdynamic -lstdc++ -o ./workdir/drivers/driver$i
done

