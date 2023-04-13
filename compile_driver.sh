#!/bin/bash

CXX=$LLVM_DIR/bin/clang++

MAX_DRIVER=10
for i in `seq 0 $(expr $MAX_DRIVER - 1)`
do
    echo "Driver"$i
    $CXX -g -std=c++11  -fsanitize=fuzzer,address -I/tmp/libtiff/work/include  ./workdir/drivers/driver$i.cc /tmp/libtiff/work/lib/libtiff.a /tmp/libtiff/work/lib/libtiffxx.a -lz -ljpeg -Wl,-Bstatic -llzma -Wl,-Bdynamic -lstdc++ -o ./workdir/drivers/driver$i
done

