
library.o: export CC = wllvm
library.o: export CXX = wllvm++
library.o: export LLVM_COMPILER = clang
library.o: export LLVM_LINK_NAME = llvm-link-13

library.o: library.c
	$(CC) -O2 -g -c $<
	extract-bc -b $@
	cp $@.bc ~/SVF-example
	
clean:
	rm -f library.o library.o.bc .library.o.bc