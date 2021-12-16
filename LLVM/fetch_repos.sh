#!/bin/bash

rm -r  clang lld llvm

#get LLVM
if [ ! -d llvm ]; then
wget -q --retry-connrefused --tries=100 https://github.com/llvm/llvm-project/releases/download/llvmorg-12.0.0/llvm-12.0.0.src.tar.xz
tar -xf llvm-12.0.0.src.tar.xz
mv llvm-12.0.0.src llvm
rm llvm-12.0.0.src.tar.xz
fi
echo "Done with LLVM"

#get Clang
if [ ! -d clang ]; then
wget -q --retry-connrefused --tries=100 https://github.com/llvm/llvm-project/releases/download/llvmorg-12.0.0/clang-12.0.0.src.tar.xz
tar -xf clang-12.0.0.src.tar.xz
mv clang-12.0.0.src clang
rm clang-12.0.0.src.tar.xz
fi
echo "Done with Clang"

#get lld
if [ ! -d lld ]; then
wget -q --retry-connrefused --tries=100 https://github.com/llvm/llvm-project/releases/download/llvmorg-12.0.0/lld-12.0.0.src.tar.xz
tar -xf lld-12.0.0.src.tar.xz
mv lld-12.0.0.src lld
rm lld-12.0.0.src.tar.xz
fi
echo "Done with lld"

#to install LLVM gold
if [ ! -d binutils ]; then
git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils
mkdir build
cd build
../binutils/configure --enable-gold --enable-plugins --disable-werror --enable-debug
make all-gold
cd ..
fi
echo "Done with LLVM gold"

#Set up clang, compiler-rt
cd llvm/tools
ln -s ../../clang .
cd ../../
