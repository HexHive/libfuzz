#!/bin/bash

set -e
set -x

# export LIBFUZZ=/workspaces/libfuzz/
export TARGET_NAME=cpuinfo
export TARGET=$(realpath $LIBFUZZ/analysis/$TARGET_NAME/)

# NOTE: if TOOLD_DIR is unset, I assume to find stuffs in LIBFUZZ folder
if [ -z $TOOLS_DIR ]; then
    TOOLS_DIR=$LIBFUZZ
fi

WORK=$TARGET/work
rm -rf "$WORK"
mkdir -p "$WORK"
mkdir -p "$WORK/lib" "$WORK/include"

export CC=wllvm
export CFLAGS=$CFLAGS" -Wno-unused-command-line-argument -mllvm -get-api-pass -g -O0"
export CXX=wllvm++
export CXXFLAGS=$CXXFLAGS" -Wno-unused-command-line-argument -mllvm -get-api-pass -g -O0" \
export LLVM_COMPILER=clang
export LLVM_COMPILER_PATH=$LLVM_DIR/bin

# export CC=$LIBFUZZ/LLVM/build/bin/clang
# export CXX=$LIBFUZZ/LLVM/build/bin/clang++
export LIBFUZZ_LOG_PATH=$WORK/apipass
# export CFLAGS="-mllvm -get-api-pass"


mkdir -p "$LIBFUZZ_LOG_PATH"

ls $LIBFUZZ_LOG_PATH

echo "make 1"
export REPO="$TARGET/repo"
cd $REPO

# configure compiles some shits for testing, better remove it
rm -rf $LIBFUZZ_LOG_PATH/apis.log

touch "${LIBFUZZ_LOG_PATH}/exported_functions.txt"
touch $LIBFUZZ_LOG_PATH/incomplete_types.txt
touch $LIBFUZZ_LOG_PATH/apis_clang.json
touch $LIBFUZZ_LOG_PATH/apis_llvm.json
touch $LIBFUZZ_LOG_PATH/coerce.log
        
echo cmake
echo $CC
rm -drf $REPO/CMakeCache.txt
rm -drf $REPO/CMakeFiles
cmake . -G Ninja -DCMAKE_INSTALL_PREFIX=$WORK -DBUILD_SHARED_LIBS=off \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCPUINFO_LIBRARY_TYPE=static
echo "make clean"
ninja
ninja install
LIBNAME=libcpuinfo.a
LIBLOCATION=$WORK/lib/$LIBNAME

extract-bc -b $LIBLOCATION

# this extracts the exported functions in a file, to be used later for grammar
# generations
$TOOLS_DIR/tool/misc/extract_included_functions.py -i "$WORK/include" \
    -p "$LIBFUZZ/targets/${TARGET_NAME}/public_headers.txt" \
    -e "$LIBFUZZ_LOG_PATH/exported_functions.txt" \
    -t "$LIBFUZZ_LOG_PATH/incomplete_types.txt" \
    -a "$LIBFUZZ_LOG_PATH/apis_clang.json" \
    -n "$LIBFUZZ_LOG_PATH/enum_types.txt"

# extract fields dependency from the library itself, repeat for each object
# produced
$TOOLS_DIR/condition_extractor/bin/extractor \
    $LIBLOCATION.bc \
    -interface "$LIBFUZZ_LOG_PATH/apis_clang.json" \
    -output "$LIBFUZZ_LOG_PATH/conditions.json" \
    -minimize_api "$LIBFUZZ_LOG_PATH/apis_minimized.txt" \
    -v v0 -t json -do_indirect_jumps \
    -data_layout "$LIBFUZZ_LOG_PATH/data_layout.txt"
