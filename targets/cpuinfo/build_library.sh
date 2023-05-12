#!/bin/bash
set -e

##
# Pre-requirements:
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, FLAGS, LIBS, etc...
##

# export TARGET=/tmp/libtiff

if [ ! -d "$TARGET/repo" ]; then
    echo "fetch.sh must be executed first."
    exit 1
fi

export CC=$LLVM_DIR/bin/clang
export CXX=$LLVM_DIR/bin/clang++

WORK="$TARGET/work"
rm -rf "$WORK"
mkdir -p "$WORK"
mkdir -p "$WORK/lib" "$WORK/include"

export LIBFUZZ_LOG_PATH=$WORK/apipass

echo "make 1"
cd "$TARGET/repo"
        
echo cmake
cmake . -DCMAKE_INSTALL_PREFIX=$WORK -DBUILD_SHARED_LIBS=off \
        -DENABLE_STATIC=on -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS_DEBUG="-v -g " \
        -DCMAKE_CXX_FLAGS_DEBUG="-v -g" \
        -DCPUINFO_LIBRARY_TYPE=static
echo "make clean"
make -j$(nproc) clean
echo "make"
make -j$(nproc) install

echo "[INFO] Library installed in: $WORK"
