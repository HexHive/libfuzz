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

# source ${FUZZER}/instrument.sh

# echo "cpy 1"
# cp "$WORK/bin/tiffcp" "$OUT/"

# echo "cxx 1"
# $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
#     contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc -o $OUT/tiff_read_rgba_fuzzer \
#     $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a -lz -ljpeg -Wl,-Bstatic -llzma -Wl,-Bdynamic \
#     $LDFLAGS $LIBS

# PROGRAM_W_EXT=`ls $SHARED/drivers/ | grep "${PROGRAM}\.*.cc"`

CXX=$LLVM_DIR/bin/clang++
CC=$LLVM_DIR/bin/clang

DRIVER_FOLDER=${LIBFUZZ}/workdir/${TARGET_NAME}/drivers
echo "Compiling: ${DRIVER_FOLDER}/${DRIVER}.cc"

# $CXX $CXXFLAGS -std=c++11 -I$WORK/include \
#     $SHARED/drivers/$PROGRAM_W_EXT -o $OUT/$PROGRAM \
#     $WORK/lib/libtiffxx.a $WORK/lib/libtiff.a -lz -ljpeg -Wl,-Bstatic -llzma -Wl,-Bdynamic \
#    $LDFLAGS $LIBS



for d in `ls ${DRIVER_FOLDER}/${DRIVER}.cc`
do
    echo "Driver: $d"
    $CXX -g -std=c++11  -fsanitize=fuzzer,address -I/${TARGET}/work/include \
        $d ${TARGET}/work/lib/libtiff.a ${TARGET}/work/lib/libtiffxx.a \
        -lz -ljpeg -Wl,-Bstatic -llzma -Wl,-Bdynamic -lstdc++ -o "${d%%.*}"
done

for d in ` find ${DRIVER_FOLDER} -type f -executable`
do
    echo "Fuzzing ${TIMEOUT}: $d"
    DRIVER_NAME=$(basename $d)
    CRASHES_DIR=${LIBFUZZ}/workdir/${TARGET_NAME}/crashes/${DRIVER_NAME%%.*}
    mkdir -p ${CRASHES_DIR}
    timeout $TIMEOUT $d \
        ${LIBFUZZ}/workdir/${TARGET_NAME}/corpus/${DRIVER_NAME%%.*} \
        -artifact_prefix=${CRASHES_DIR} || echo "Done: $d"
done