
```bash
mkdir build
cd build
cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Debug -DLLVM_ENABLE_PROJECTS="clang;compiler-rt" ../llvm
make
```
```bash
git clone \
    git@github.com:cyruscyliu/virtfuzz-llvm-project.git --depth=1
cp evaluation/run.sh .
sudo bash run.sh # Enter the container
pushd llvm-project && mkdir build-custom && pushd build-custom
# remove lld from the options
cmake -G Ninja -DLLVM_ENABLE_PROJECTS="clang;compiler-rt;lld" \
    -DLLVM_TARGETS_TO_BUILD=X86 -DLLVM_OPTIMIZED_TABLEGEN=ON ../llvm/
ninja clang compiler-rt llvm-symbolizer llvm-profdata llvm-cov \
    llvm-config lld llvm-dis opt
popd && popd

# later..

ninja clang compiler-rt llvm-symbolizer llvm-profdata llvm-cov \
    llvm-config lld llvm-dis opt
```