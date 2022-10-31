
#!/bin/bash

set -e

LLVMHome="llvm-13.0.0-custom.obj"

cd /root

# copied from SVF/build.sh build_llvm_from_source
mkdir "$LLVMHome"
echo "Downloading LLVM source..."
wget https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-13.0.0.zip -O llvm.zip
echo "Unzipping LLVM source..."
mkdir llvm-source
unzip llvm.zip -d llvm-source
echo "Building LLVM..."
mkdir llvm-build
cd llvm-build
# /*/ is a dirty hack to get llvm-project-llvmorg-version...
cmake -DCMAKE_INSTALL_PREFIX="/root/$LLVMHome" ../llvm-source/*/llvm
# to replace with ./build.sh -- later
make -j${jobs}
make install
cd ..


cd -