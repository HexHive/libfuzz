#!/bin/bash
set -e

export LIBFUZZ=/workspaces/libfuzz/
export TARGET=$LIBFUZZ/analysis/openssl/ 

./fetch.sh

WORK="$TARGET/work"
rm -rf "$WORK"
mkdir -p "$WORK"
mkdir -p "$WORK/lib" "$WORK/include"

export CC=wllvm
export CXX=wllvm++
export LLVM_COMPILER=clang
export LLVM_COMPILER_PATH=$LLVM_DIR/bin
export LIBFUZZ_LOG_PATH=$WORK/apipass
CFLAGS="-g -O0"

mkdir -p "$LIBFUZZ_LOG_PATH"

# build the libpng library
cd "$TARGET/repo"

# CONFIGURE_FLAGS=""
# if [[ $CFLAGS = *sanitize=memory* ]]; then
#   CONFIGURE_FLAGS="no-asm"
# fi

# the config script supports env var LDLIBS instead of LIBS
export LDLIBS="$LIBS"

./config --debug $CFLAGS -fno-sanitize=alignment --prefix="$WORK"

# configure compiles some shits for testing, better remove it
rm -f $LIBFUZZ_LOG_PATH/apis_clang.json

touch $LIBFUZZ_LOG_PATH/exported_functions.txt
touch $LIBFUZZ_LOG_PATH/incomplete_types.txt
touch $LIBFUZZ_LOG_PATH/apis_clang.json
touch $LIBFUZZ_LOG_PATH/apis_llvm.json
touch $LIBFUZZ_LOG_PATH/coerce.log

# CXXFLAGS="-fPIC -DOPENSSL_PIC"

make -j$(nproc) clean
make -j$(nproc) LDCMD="$CXX $CXXFLAGS"
make install
# # make -j$(nproc) 

extract-bc -b $WORK/lib/libssl.a
extract-bc -b $WORK/lib/libcrypto.a

# for later
# $LLVM_DIR/bin/llvm-link libcrypto.a.bc libssl.a.bc -o libfull.bc

# this extracts the exported functions in a file, to be used later for grammar generations
$LIBFUZZ/tool/misc/extract_included_functions.py -i "$WORK/include/openssl" \
    -p "$LIBFUZZ/targets/${TARGET_NAME}/public_headers.txt" \
    -e "$LIBFUZZ_LOG_PATH/exported_functions.txt" \
    -t "$LIBFUZZ_LOG_PATH/incomplete_types.txt" \
    -a "$LIBFUZZ_LOG_PATH/apis_clang.json" \
    -n "$LIBFUZZ_LOG_PATH/enum_types.txt"

$TOOLS_DIR/condition_extractor/bin/extractor \
    $WORK/lib/libssl.a.bc \
    -interface "$LIBFUZZ_LOG_PATH/apis_clang.json" \
    -output "$LIBFUZZ_LOG_PATH/conditions_libssl.json" \
    -minimize_api "$LIBFUZZ_LOG_PATH/apis_minimized_libssl.txt" \
    -v v0 -t json -do_indirect_jumps \
    -data_layout "$LIBFUZZ_LOG_PATH/data_layout_libssl.txt"

# TODO: this should get the list of apis, not a single functions
$TOOLS_DIR/condition_extractor/bin/extractor \
    $WORK/lib/libcrypto.a.bc \
    -interface "$LIBFUZZ_LOG_PATH/apis_clang.json" \
    -output "$LIBFUZZ_LOG_PATH/conditions_libcrypto.json" \
    -minimize_api "$LIBFUZZ_LOG_PATH/apis_minimized_libcrypto.txt" \
    -v v0 -t json -do_indirect_jumps \
    -data_layout "$LIBFUZZ_LOG_PATH/data_layout_libcrypto.txt"