
library.o: export CC = wllvm
library.o: export CXX = wllvm++
library.o: export LLVM_COMPILER = clang
library.o: export LLVM_COMPILER_PATH=/root/SVF/llvm-13.0.0.obj/bin
# library.o: export LLVM_CC_NAME = clang-13
# library.o: export LLVM_LINK_NAME = llvm-link-13

library.o: library.c
	$(CC) -O3 -g -c $<
	extract-bc -b $@
	/root/SVF/llvm-13.0.0.obj/bin/llvm-dis $@.bc
	
clean:
	rm -f library.o library.o.bc .library.o.bc library.o.svf.bc svfg_final.dot library.o.ll