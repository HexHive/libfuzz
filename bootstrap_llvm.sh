#!/bin/bash

# make sure to be in the right folder
cd ${LIBFUZZ}

# I need to install system clang
sudo ./update-alternatives-clang.sh 12 200

# download LLVM 14
./install_llvm.sh

# compile my LLVM 14
./llvm-project/build.sh 