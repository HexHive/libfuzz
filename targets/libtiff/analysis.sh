#!/bin/bash

export TARGET=/workspace/libfuzz/analysis/libtiff/ 

./fetch.sh

WORK="$TARGET/work"
rm -rf "$WORK"
mkdir -p "$WORK"
mkdir -p "$WORK/lib" "$WORK/include"

export CC=/workspace/libfuzz/LLVM/build/bin/clang
export CXX=/workspace/libfuzz/LLVM/build/bin/clang++
export LIBFUZZ_LOG_PATH=$WORK/apipass
export CFLAGS="-mllvm -get-api-pass"

mkdir -p $LIBFUZZ_LOG_PATH

echo "make 1"
cd "$TARGET/repo"
./autogen.sh
echo "./configure"
# ./configure --disable-shared --prefix="$WORK"
./configure --disable-shared --prefix="$WORK" CFLAGS="-mllvm -get-api-pass" CC=/workspace/libfuzz/LLVM/build/bin/clang CXX=/workspace/libfuzz/LLVM/build/bin/clang++

# configure compiles some shits for testing, better remove it
rm $LIBFUZZ_LOG_PATH/apis.log

echo "make clean"
make -j$(nproc) clean
echo "make"
make -j$(nproc)
echo "make install"
make install