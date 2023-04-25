#!/bin/bash

LLVM_VERSION=12.0.0

cd "$HOME" || exit

rm -rf  clang llvm compiler-rt

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

#get compiler-rt
if [ ! -d compiler-rt ]; then
wget -q --retry-connrefused --tries=100 https://github.com/llvm/llvm-project/releases/download/llvmorg-$LLVM_VERSION/compiler-rt-$LLVM_VERSION.src.tar.xz
tar -xf compiler-rt-$LLVM_VERSION.src.tar.xz
mv compiler-rt-$LLVM_VERSION.src compiler-rt
rm compiler-rt-$LLVM_VERSION.src.tar.xz
fi
echo "Done with compiler-rt"

#to install LLVM gold
if [ ! -d binutils ]; then
git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils
mkdir build
cd build || exit
../binutils/configure --enable-gold --enable-plugins --disable-werror --enable-debug
make all-gold -j
cd ..
fi
echo "Done with LLVM gold"

#Set up clang, compiler-rt
cd llvm/tools || exit
ln -s ../../clang .
cd ../../

cd llvm/projects || exit
ln -s ../../compiler-rt .
cd ../../

cd - || exit
