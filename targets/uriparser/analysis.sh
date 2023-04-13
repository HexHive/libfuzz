#!/bin/bash

export LIBFUZZ=/workspaces/libfuzz/
export TARGET=$LIBFUZZ/analysis/libtiff/ 

./fetch.sh

WORK="$TARGET/work"
rm -rf "$WORK"
mkdir -p "$WORK"
mkdir -p "$WORK/lib" "$WORK/include"

export CC=wllvm
export CXX=wllvm++
export LLVM_COMPILER=clang
export LLVM_COMPILER_PATH=$LLVM_DIR/bin

# export CC=$LIBFUZZ/LLVM/build/bin/clang
# export CXX=$LIBFUZZ/LLVM/build/bin/clang++
export LIBFUZZ_LOG_PATH=$WORK/apipass
# export CFLAGS="-mllvm -get-api-pass"


mkdir -p $LIBFUZZ_LOG_PATH

echo "make 1"
cd "$TARGET/repo"
./autogen.sh
echo "./configure"
# ./configure --disable-shared --prefix="$WORK" \
#                                 CC=wllvm CXX=wllvm++
./configure --disable-shared --prefix="$WORK" \
                                CC=wllvm CXX=wllvm++ \
                                CXXFLAGS="-mllvm -get-api-pass -g -O0" \
                                CFLAGS="-mllvm -get-api-pass -g -O0"

# configure compiles some shits for testing, better remove it
rm $LIBFUZZ_LOG_PATH/apis.log

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

extract-bc -b $WORK/lib/libtiffxx.a
extract-bc -b $WORK/lib/libtiff.a

# this extracts the exported functions in a file, to be used later for grammar generations
$LIBFUZZ/tool/misc/extract_included_functions.py -i "$WORK/include" \
                                                 -e "$LIBFUZZ_LOG_PATH/exported_functions.txt" \
                                                 -t "$LIBFUZZ_LOG_PATH/incomplete_types.txt" \
                                                 -a "$LIBFUZZ_LOG_PATH/apis_clang.json"

# TODO: this should get the list of apis, not a single functions
# $LIBFUZZ/condition_extractor/bin/extractor $WORK/lib/libtiff.a.bc -function TIFFClientOpen -output $LIBFUZZ_LOG_PATH/conditions.json -v v1 -t json