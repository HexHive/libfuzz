#!/bin/bash

#This script softlinks our modified files into the LLVM source tree

#Path to llvm source tree
llvm=`pwd`/llvm
clang=`pwd`/clang
src=`pwd`/src

#llvm include
llvminc=$llvm/include/llvm

#llvm pass
llvmpass=$llvm/lib/Transforms/GetApi

#llvm passutil
llvmutil=$llvm/lib/Transforms/Utils

# llvm include
llvminclude=$llvm/include/llvm/Transforms/Utils

#install clang files
rm $clang/lib/CodeGen/BackendUtil.cpp
rm $clang/lib/CodeGen/CGCall.cpp
rm $clang/include/clang/CodeGen/BackendUtil.h
rm $clang/lib/CodeGen/CMakeLists.txt

ln -s $src/clang-code/BackendUtil.cpp $clang/lib/CodeGen/BackendUtil.cpp
ln -s $src/clang-code/CGCall.cpp $clang/lib/CodeGen/CGCall.cpp
ln -s $src/clang-code/BackendUtil.h $clang/include/clang/CodeGen/BackendUtil.h
ln -s $src/clang-code/CMakeList_CodeGen.txt $clang/lib/CodeGen/CMakeLists.txt

#install llvm files
rm -Rf $llvmpass
rm $llvm/lib/Transforms/CMakeLists.txt
rm $llvm/lib/Transforms/Utils/CMakeLists.txt

rm $llvmutil/LibfuzzUtil.cpp
rm $llvminclude/LibfuzzUtil.h

rm $llvm/include/llvm/Transforms/Instrumentation.h

mkdir -p $llvmpass

ln -s $src/llvm-pass/GetApi.cpp $llvmpass
ln -s $src/llvm-pass/GetApi.exports $llvmpass
ln -s $src/llvm-pass/CMakeLists.txt $llvmpass
ln -s $src/llvm-pass/CMakeLists_Transform.txt $llvm/lib/Transforms/CMakeLists.txt
ln -s $src/llvm-pass/CMakeLists_Utils.txt $llvm/lib/Transforms/Utils/CMakeLists.txt

ln -s $src/llvm-pass/LibfuzzUtil.cpp $llvmutil
ln -s $src/llvm-pass/LibfuzzUtil.h $llvminclude

ln -s $src/llvm-pass/Instrumentation.h $llvm/include/llvm/Transforms/Instrumentation.h