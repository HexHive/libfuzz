#!/bin/bash

rm -r  clang lld llvm

LLVM_VERSION=12.0.0

cd $HOME

#get LLVM
if [ ! -d llvm ]; then
wget -q --retry-connrefused --tries=100 https://github.com/llvm/llvm-project/releases/download/llvmorg-$LLVM_VERSION/llvm-$LLVM_VERSION.src.tar.xz
tar -xf llvm-$LLVM_VERSION.src.tar.xz
mv llvm-$LLVM_VERSION.src llvm
rm llvm-$LLVM_VERSION.src.tar.xz
fi
echo "Done with LLVM"

#get Clang
if [ ! -d clang ]; then
wget -q --retry-connrefused --tries=100 https://github.com/llvm/llvm-project/releases/download/llvmorg-$LLVM_VERSION/clang-$LLVM_VERSION.src.tar.xz
tar -xf clang-$LLVM_VERSION.src.tar.xz
mv clang-$LLVM_VERSION.src clang
rm clang-$LLVM_VERSION.src.tar.xz
fi
echo "Done with Clang"

#get lld
if [ ! -d lld ]; then
wget -q --retry-connrefused --tries=100 https://github.com/llvm/llvm-project/releases/download/llvmorg-$LLVM_VERSION/lld-$LLVM_VERSION.src.tar.xz
tar -xf lld-$LLVM_VERSION.src.tar.xz
mv lld-$LLVM_VERSION.src lld
rm lld-$LLVM_VERSION.src.tar.xz
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

cd -