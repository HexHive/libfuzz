#!/bin/bash

PROJECTHOME=$(pwd)
# LLVMHome="llvm-13.0.0.obj"
Z3Home="z3.obj"
export SVF_DIR="${HOME}/SVF"
# export LLVM_DIR=$SVF_DIR/$LLVMHome
export Z3_DIR=$SVF_DIR/$Z3Home
export PATH=$LLVM_DIR/bin:$PATH
export PATH=$PROJECTHOME/bin:$PATH
echo "export LLVM_DIR=$LLVM_DIR \
export Z3_DIR=$Z3_DIR \
export PATH=$LLVM_DIR/bin:$PROJECTHOME/bin:$PATH" >> ~/.bashrc
echo "LLVM_DIR=$LLVM_DIR"
echo "SVF_DIR=$SVF_DIR"
echo "Z3_DIR=$Z3_DIR"
