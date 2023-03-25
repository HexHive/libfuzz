CC=${LLVM_DIR}/bin/clang++

TARGET=driver0

${TARGET}: ${TARGET}.cc
	${CC} -g $< -fsanitize="fuzzer,address" -o $@

run: ${TARGET}
	./$<

clean:
	rm -f ${TARGET} crash-* leak-*