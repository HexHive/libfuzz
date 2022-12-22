LLVM_DIR = /root/llvm
BUILD_DIR = /root/llvm-build
# LLVM_DIR = /home/tregua/llvm
# BUILD_DIR = /home/tregua/llvm-build


all:
	mkdir -p ${BUILD_DIR}
	(cd ${BUILD_DIR} && \
	  CC=clang CXX=clang++ \
	  cmake -G "Ninja"\
	  -DCMAKE_C_COMPILER=clang \
	  -DCMAKE_CXX_COMPILER=clang++ \
	  -DLLVM_ENABLE_ASSERTIONS=OFF \
	  -DLLVM_BINUTILS_INCDIR="${BUILD_DIR}/../binutils/include" \
	  -DLLVM_BUILD_TESTS=OFF \
	  -DLLVM_BUILD_EXAMPLES=OFF \
	  -DLLVM_INCLUDE_TESTS=OFF\
	  -DLLVM_INCLUDE_EXAMPLES=OFF \
	  -DLLVM_USE_SPLIT_DWARF=ON \
	  -DLLVM_OPTIMIZED_TABLEGEN=ON \
	  -DBUILD_SHARED_LIBS=OFF \
	  -DLLVM_USE_LINKER=gold \
	  -DLLVM_ENABLE_BINDINGS=OFF \
	${LLVM_DIR})
	(ninja -C ${BUILD_DIR})
	cd -

# test:
# 	(cd ${BUILD_DIR} && ninja check-asan)

rebuild:
	ninja -C ${BUILD_DIR}

clean:
	rm -rf ${BUILD_DIR}

.PHONY: all test clean rebuild
