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

echo "make 1"
cd "$TARGET/repo"
        
echo "make clean"
make -j$(nproc) clean
echo "make"
make -j$(nproc) OUT="$WORK/lib" CC_STATIC_LIBRARY\(libminijail.pie.a\)
cp *.h $WORK/include

echo "[INFO] Library installed in: $WORK"
