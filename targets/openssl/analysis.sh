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
CFLAGS="-mllvm -get-api-pass"

mkdir -p "$LIBFUZZ_LOG_PATH"

# build the libpng library
cd "$TARGET/repo"

CONFIGURE_FLAGS=""
if [[ $CFLAGS = *sanitize=memory* ]]; then
  CONFIGURE_FLAGS="no-asm"
fi

# the config script supports env var LDLIBS instead of LIBS
export LDLIBS="$LIBS"

./config --debug -DPEDANTIC \
    -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared no-module \
    enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 enable-ssl3 \
    enable-ssl3-method enable-nextprotoneg enable-weak-ssl-ciphers \
    $CFLAGS -fno-sanitize=alignment $CONFIGURE_FLAGS --prefix="$WORK"

# configure compiles some shits for testing, better remove it
rm -f $LIBFUZZ_LOG_PATH/apis.log

touch $LIBFUZZ_LOG_PATH/exported_functions.txt
touch $LIBFUZZ_LOG_PATH/incomplete_types.txt
touch $LIBFUZZ_LOG_PATH/apis_clang.json
touch $LIBFUZZ_LOG_PATH/coerce.log

CXXFLAGS="-fPIC -DOPENSSL_PIC"

make -j$(nproc) clean
make -j$(nproc) LDCMD="$CXX $CXXFLAGS"
make install
make -j$(nproc) 

extract-bc -b $WORK/lib/libssl.a

# this extracts the exported functions in a file, to be used later for grammar generations
$LIBFUZZ/tool/misc/extract_included_functions.py -i "$WORK/include/openssl" \
                                                 -e "$LIBFUZZ_LOG_PATH/exported_functions.txt" \
                                                 -t "$LIBFUZZ_LOG_PATH/incomplete_types.txt" \
                                                 -a "$LIBFUZZ_LOG_PATH/apis_clang.json"

# TODO: this should get the list of apis, not a single functions
$LIBFUZZ/condition_extractor/bin/extractor $WORK/lib/libssl.a.bc -function ssl3_get_cipher_by_id -output $LIBFUZZ_LOG_PATH/conditions.json -v v0 -t json
echo "$LIBFUZZ_LOG_PATH/conditions.json"
