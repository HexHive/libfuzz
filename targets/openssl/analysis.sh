#!/bin/bash
set -e

export LIBFUZZ=/workspace/libfuzz/
export TARGET=$LIBFUZZ/analysis/openssl/ 

./fetch.sh

WORK="$TARGET/work"
rm -rf "$WORK"
mkdir -p "$WORK"
mkdir -p "$WORK/lib" "$WORK/include"

export CC=$LIBFUZZ/LLVM/build/bin/clang
export CXX=$LIBFUZZ/LLVM/build/bin/clang++
export LIBFUZZ_LOG_PATH=$WORK/apipass
# export CFLAGS="-mllvm -get-api-pass"
CFLAGS="-mllvm -get-api-pass"

mkdir -p $LIBFUZZ_LOG_PATH

# build the libpng library
cd "$TARGET/repo"

CONFIGURE_FLAGS=""
if [[ $CFLAGS = *sanitize=memory* ]]; then
  CONFIGURE_FLAGS="no-asm"
fi

# the config script supports env var LDLIBS instead of LIBS
export LDLIBS="$LIBS"

# # -fPIC -DOPENSSL_PIC
# ./config --debug enable-fuzz-libfuzzer enable-fuzz-afl disable-tests -DPEDANTIC \
#     -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared no-module \
#     enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 enable-ssl3 \
#     enable-ssl3-method enable-nextprotoneg enable-weak-ssl-ciphers \
#     $CFLAGS -fno-sanitize=alignment $CONFIGURE_FLAGS 

./config --debug -DPEDANTIC \
    -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared no-module \
    enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 enable-ssl3 \
    enable-ssl3-method enable-nextprotoneg enable-weak-ssl-ciphers \
    $CFLAGS -fno-sanitize=alignment $CONFIGURE_FLAGS --prefix="$WORK"

# configure compiles some shits for testing, better remove it
rm -f $LIBFUZZ_LOG_PATH/apis.log

touch $LIBFUZZ_LOG_PATH/exported_functions.txt
touch $LIBFUZZ_LOG_PATH/incomplete_types.txt
touch $LIBFUZZ_LOG_PATH/apis.log
touch $LIBFUZZ_LOG_PATH/coerce.log

CXXFLAGS="-fPIC -DOPENSSL_PIC"

make -j$(nproc) clean
make -j$(nproc) LDCMD="$CXX $CXXFLAGS"
make install
# make -j$(nproc) 

# this extracts the exported functions in a file, to be used later for grammar generations
$LIBFUZZ/tool/misc/extract_included_functions.py -i "$WORK/include" -e "$LIBFUZZ_LOG_PATH/exported_functions.txt" -t "$LIBFUZZ_LOG_PATH/incomplete_types.txt"