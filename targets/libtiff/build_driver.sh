#!/bin/bash
set -e

##
# Pre-requirements:
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, FLAGS, LIBS, etc...
##

# if [ ! -d "$TARGET/repo" ]; then
#     echo "fetch.sh must be executed first."
#     exit 1
# fi

WORK="$TARGET/work"
# rm -rf "$WORK"
# mkdir -p "$WORK"
# mkdir -p "$WORK/lib" "$WORK/include"

# echo "make 1"
cd "$TARGET/repo"
# ./autogen.sh
# echo "./configure"
# ./configure --disable-shared --prefix="$WORK"
# echo "make clean"
# make -j$(nproc) clean
# echo "make"
# make -j$(nproc)
# echo "make install"
# make install

source ${FUZZER}/instrument.sh

# echo "cpy 1"
# cp "$WORK/bin/tiffcp" "$OUT/"

# echo "cxx 1"
# $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
#     contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc -o $OUT/tiff_read_rgba_fuzzer \
#     $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a -lz -ljpeg -Wl,-Bstatic -llzma -Wl,-Bdynamic \
#     $LDFLAGS $LIBS

PROGRAM_W_EXT=`ls $SHARED/drivers/ | grep "${PROGRAM}\.*.cc"`

echo "Compiling: $SHARED/drivers/$PROGRAM_W_EXT"

$CXX $CXXFLAGS -std=c++11 -I$WORK/include \
    $SHARED/drivers/$PROGRAM_W_EXT -o $OUT/$PROGRAM \
    $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a -lz -ljpeg -Wl,-Bstatic -llzma -Wl,-Bdynamic \
    $LDFLAGS $LIBS

    
