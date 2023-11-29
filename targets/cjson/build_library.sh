#!/bin/bash

set -e
set -x

# NOTE: if TOOLD_DIR is unset, I assume to find stuffs in LIBFUZZ folder
if [ -z "$TOOLS_DIR" ]; then
    TOOLS_DIR=$LIBFUZZ
fi

WORK="$TARGET/work"
rm -rf "$WORK"
mkdir -p "$WORK"
mkdir -p "$WORK/lib" "$WORK/include"

export LLVM_COMPILER_PATH=$LLVM_DIR/bin
export CC="$LLVM_COMPILER_PATH"/clang
export CXX="$LLVM_COMPILER_PATH"/clang++

echo "make 1"
mkdir -p "$TARGET/repo/cJSON_build"
cd "$TARGET/repo/cJSON_build"

# Compile library for coverage
cmake .. -DCMAKE_INSTALL_PREFIX="$WORK" -DBUILD_SHARED_AND_STATIC_LIBS=On \
        -DBUILD_SHARED_LIBS=off -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS_DEBUG="-fprofile-instr-generate -fcoverage-mapping -g" \
        -DCMAKE_CXX_FLAGS_DEBUG="-fprofile-instr-generate -fcoverage-mapping -g"

echo "make clean"
make -j"$(nproc)" clean
echo "make"
make -j"$(nproc)"
echo "make install"
make install

mv "$WORK"/lib/libcjson.a "$WORK"/lib/libcjson_profile.a

cd ..
mkdir -p "$TARGET/repo/aom_build_cluster"
cd "$TARGET/repo/aom_build_cluster"

# Compile library for clustering
cmake .. -DCMAKE_INSTALL_PREFIX="$WORK" -DBUILD_SHARED_AND_STATIC_LIBS=On \
        -DBUILD_SHARED_LIBS=off -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS_DEBUG="-fsanitize=fuzzer-no-link,address -g" \
        -DCMAKE_CXX_FLAGS_DEBUG="-fsanitize=fuzzer-no-link,address -g"

echo "make clean"
make -j"$(nproc)" clean
echo "make"
make -j"$(nproc)"
echo "make install"
make install

mv "$WORK"/lib/libcjson.a "$WORK"/lib/libcjson_cluster.a

cd ..
mkdir -p "$TARGET/repo/aom_build_fuzz"
cd "$TARGET/repo/aom_build_fuzz"

# Compile library for fuzzing
cmake .. -DCMAKE_INSTALL_PREFIX="$WORK" -DBUILD_SHARED_AND_STATIC_LIBS=On \
        -DBUILD_SHARED_LIBS=off -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_FLAGS_RELEASE="-fsanitize=fuzzer-no-link,address" \
        -DCMAKE_CXX_FLAGS_RELELASE="-fsanitize=fuzzer-no-link,address"

echo "make clean"
make -j"$(nproc)" clean
echo "make"
make -j"$(nproc)"
echo "make install"
make install
# configure compiles some shits for testing, better remove it
echo "[INFO] Library installed in: $WORK"
