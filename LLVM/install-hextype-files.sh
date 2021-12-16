#!/bin/bash

#This script softlinks our modified files into the LLVM source tree

#Path to llvm source tree
llvm=`pwd`/llvm
clang=`pwd`/clang
src=`pwd`/src
runtime=`pwd`/compiler-rt

#llvm include
llvminc=$llvm/include/llvm

#llvm pass
llvmpass=$llvm/lib/Transforms/Instrumentation

#llvm passutil
llvmutil=$llvm/lib/Transforms/Utils

#llvm include
llvminclude=$llvm/include/llvm/Transforms/Utils

#install clang files
rm $clang/lib/AST/DeclCXX.cpp
rm $clang/include/clang/AST/CXXRecordDeclDefinitionBits.def
rm $clang/include/clang/AST/DeclCXX.h
rm $clang/include/clang/Driver/SanitizerArgs.h
rm $clang/include/clang/Basic/Sanitizers.def
rm $clang/include/clang/Basic/Features.def
rm $clang/lib/Driver/ToolChain.cpp
rm $clang/lib/Driver/ToolChains/Darwin.cpp
rm $clang/lib/Driver/ToolChains/CommonArgs.cpp
rm $clang/lib/Sema/SemaDeclCXX.cpp
rm $clang/lib/Sema/SemaInit.cpp
rm $clang/lib/Sema/SemaDecl.cpp
rm $clang/lib/CodeGen/BackendUtil.cpp
rm $clang/lib/CodeGen/CGExprScalar.cpp
rm $clang/lib/CodeGen/CGExpr.cpp
rm $clang/lib/CodeGen/CodeGenModule.cpp
rm $clang/lib/CodeGen/CodeGenModule.h
rm $clang/lib/CodeGen/CodeGenFunction.cpp
rm $clang/lib/CodeGen/CodeGenFunction.h
rm $clang/lib/CodeGen/CGClass.cpp
rm $clang/lib/CodeGen/CGExprCXX.cpp
rm $clang/lib/Sema/SemaTemplateInstantiateDecl.cpp
rm $clang/lib/Sema/SemaTemplateInstantiate.cpp

ln -s $src/clang-files/DeclCXX.cpp $clang/lib/AST/DeclCXX.cpp
ln -s $src/clang-files/CXXRecordDeclDefinitionBits.def $clang/include/clang/AST/CXXRecordDeclDefinitionBits.def
ln -s $src/clang-files/DeclCXX.h $clang/include/clang/AST/DeclCXX.h
ln -s $src/clang-files/SanitizerArgs.h $clang/include/clang/Driver/SanitizerArgs.h
ln -s $src/clang-files/Sanitizers.def $clang/include/clang/Basic/Sanitizers.def
ln -s $src/clang-files/Features.def $clang/include/clang/Basic/Features.def
ln -s $src/clang-files/ToolChain.cpp $clang/lib/Driver/ToolChain.cpp
ln -s $src/clang-files/Darwin.cpp $clang/lib/Driver/ToolChains/Darwin.cpp
ln -s $src/clang-files/CommonArgs.cpp $clang/lib/Driver/ToolChains/CommonArgs.cpp
ln -s $src/clang-files/SemaDeclCXX.cpp $clang/lib/Sema/SemaDeclCXX.cpp
ln -s $src/clang-files/SemaDecl.cpp $clang/lib/Sema/SemaDecl.cpp
ln -s $src/clang-files/SemaInit.cpp $clang/lib/Sema/SemaInit.cpp
ln -s $src/clang-files/BackendUtil.cpp $clang/lib/CodeGen/BackendUtil.cpp
ln -s $src/clang-files/CGExprScalar.cpp $clang/lib/CodeGen/CGExprScalar.cpp
ln -s $src/clang-files/CGExpr.cpp $clang/lib/CodeGen/CGExpr.cpp
ln -s $src/clang-files/CodeGenModule.cpp $clang/lib/CodeGen/CodeGenModule.cpp
ln -s $src/clang-files/CodeGenModule.h $clang/lib/CodeGen/CodeGenModule.h
ln -s $src/clang-files/CodeGenFunction.cpp $clang/lib/CodeGen/CodeGenFunction.cpp
ln -s $src/clang-files/CodeGenFunction.h $clang/lib/CodeGen/CodeGenFunction.h
ln -s $src/clang-files/CGClass.cpp $clang/lib/CodeGen/CGClass.cpp
ln -s $src/clang-files/CGExprCXX.cpp $clang/lib/CodeGen/CGExprCXX.cpp
ln -s $src/clang-files/SemaTemplateInstantiateDecl.cpp $clang/lib/Sema/SemaTemplateInstantiateDecl.cpp
ln -s $src/clang-files/SemaTemplateInstantiate.cpp $clang/lib/Sema/SemaTemplateInstantiate.cpp

#install llvm files
rm $llvmpass/HexTypePass.cpp
rm $llvmutil/HexTypeUtil.cpp
rm $llvminclude/HexTypeUtil.h
rm $llvm/include/llvm/InitializePasses.h
rm $llvm/include/llvm/Transforms/Instrumentation.h
rm $llvm/lib/Transforms/Utils/CMakeLists.txt
rm $llvm/lib/Transforms/Instrumentation/CMakeLists.txt
rm $llvm/lib/Analysis/MemoryBuiltins.cpp

ln -s $src/llvm-files/HexTypePass.cpp $llvmpass
ln -s $src/llvm-files/HexTypeUtil.cpp $llvmutil
ln -s $src/llvm-files/HexTypeUtil.h $llvminclude
ln -s $src/llvm-files/InitializePasses.h $llvminc
ln -s $src/llvm-files/Instrumentation.h $llvm/include/llvm/Transforms/Instrumentation.h
ln -s $src/llvm-files/UtilsCMakeLists.txt $llvm/lib/Transforms/Utils/CMakeLists.txt
ln -s $src/llvm-files/InstrumentationCMakeLists.txt $llvm/lib/Transforms/Instrumentation/CMakeLists.txt
ln -s $src/llvm-files/MemoryBuiltins.cpp $llvm/lib/Analysis/MemoryBuiltins.cpp

#include compiler-rt file
rm $runtime/lib/CMakeLists.txt
rm -dr $runtime/lib/typeplus 
rm $runtime/lib/typeplus/CMakeLists.txt
rm $runtime/lib/typeplus/typeplus.cc
rm $runtime/lib/typeplus/typeplus.h

ln -s $src/compiler-rt-files/lib_cmakelists.txt $runtime/lib/CMakeLists.txt
mkdir $runtime/lib/typeplus
ln -s $src/compiler-rt-files/lib_typeplus_cmakelists.txt $runtime/lib/typeplus/CMakeLists.txt
ln -s $src/compiler-rt-files/typeplus.cc $runtime/lib/typeplus/typeplus.cc
ln -s $src/compiler-rt-files/typeplus.h $runtime/lib/typeplus/typeplus.h

#install clang plugin files
mkdir -p $clang/examples/TypeXXCodeChecker/

rm $clang/examples/TypeXXCodeChecker/CMakeLists.txt
rm $clang/examples/TypeXXCodeChecker/README.txt
rm $clang/examples/TypeXXCodeChecker/TypeXXCodeChecker.cpp
rm $clang/examples/TypeXXCodeChecker/TypeXXCodeChecker.exports

rm $clang/lib/Sema/AnalysisBasedWarnings.cpp

rm $clang/examples/CMakeLists.txt

ln -s $src/clang-plugin/CMakeLists.txt $clang/examples/TypeXXCodeChecker/CMakeLists.txt
ln -s $src/clang-plugin/README.txt $clang/examples/TypeXXCodeChecker/README.txt
ln -s $src/clang-plugin/TypeXXCodeChecker.cpp $clang/examples/TypeXXCodeChecker/TypeXXCodeChecker.cpp
ln -s $src/clang-plugin/TypeXXCodeChecker.exports $clang/examples/TypeXXCodeChecker/TypeXXCodeChecker.exports

ln -s $src/clang-plugin/CMakeLists_examples.txt $clang/examples/CMakeLists.txt

ln -s $src/clang-plugin/AnalysisBasedWarnings.cpp $clang/lib/Sema/AnalysisBasedWarnings.cpp