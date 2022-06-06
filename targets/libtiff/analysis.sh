#!/bin/bash

export LIBFUZZ=/workspace/libfuzz/
export TARGET=$LIBFUZZ/analysis/libtiff/ 

./fetch.sh

WORK="$TARGET/work"
rm -rf "$WORK"
mkdir -p "$WORK"
mkdir -p "$WORK/lib" "$WORK/include"

export CC=$LIBFUZZ/LLVM/build/bin/clang
export CXX=$LIBFUZZ/LLVM/build/bin/clang++
export LIBFUZZ_LOG_PATH=$WORK/apipass
export CFLAGS="-mllvm -get-api-pass"

mkdir -p $LIBFUZZ_LOG_PATH

echo "make 1"
cd "$TARGET/repo"
./autogen.sh
echo "./configure"
# ./configure --disable-shared --prefix="$WORK"
./configure --disable-shared --prefix="$WORK" CFLAGS="-mllvm -get-api-pass" CC=$LIBFUZZ/LLVM/build/bin/clang CXX=$LIBFUZZ/LLVM/build/bin/clang++

# configure compiles some shits for testing, better remove it
# rm $LIBFUZZ_LOG_PATH/apis.log

touch $LIBFUZZ_LOG_PATH/exported_functions.txt
touch $LIBFUZZ_LOG_PATH/incomplete_types.txt
touch $LIBFUZZ_LOG_PATH/apis_clang.json
touch $LIBFUZZ_LOG_PATH/apis_llvm.json
touch $LIBFUZZ_LOG_PATH/coerce.log

echo "make clean"
make -j$(nproc) clean
echo "make"
make -j$(nproc)
echo "make install"
make install

# this extracts the exported functions in a file, to be used later for grammar generations
$LIBFUZZ/tool/misc/extract_included_functions.py -i "$WORK/include" \
                                                 -e "$LIBFUZZ_LOG_PATH/exported_functions.txt" \
                                                 -t "$LIBFUZZ_LOG_PATH/incomplete_types.txt" \
                                                 -a "$LIBFUZZ_LOG_PATH/apis_clang.json"