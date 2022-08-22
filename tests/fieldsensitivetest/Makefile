
library.o: export CC = wllvm
library.o: export CXX = wllvm++
library.o: export LLVM_COMPILER = clang
library.o: export LLVM_CC_NAME = clang-13
library.o: export LLVM_LINK_NAME = llvm-link-13

library.o: library.c
	$(CC) -O2 -g -c $<
	extract-bc -b $@
	
clean:
	rm -f library.o library.o.bc .library.o.bc