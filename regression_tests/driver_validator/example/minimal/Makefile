export CC = wllvm
export CXX = wllvm++
export LLVM_COMPILER=clang
export LLVM_COMPILER_PATH=${LLVM_DIR}/bin
export AR = ${LLVM_DIR}/bin/llvm-ar

TARGET = library
EXTRACTOR = /workspaces/libfuzz/condition_extractor/bin/extractor
LLVM_DIS = ${LLVM_DIR}/bin/llvm-dis
WPA = /root/SVF/Release-build/bin/wpa
EXTRACT_BC = extract-bc
FUNCTION = api1
DRIVER = driver

$(DRIVER): $(DRIVER).o $(TARGET).a
	$(CC) -O0 -g -o $@ $< $(TARGET).a

$(DRIVER)_shared: $(DRIVER).o $(TARGET).so
	$(CC) -O0 -g -o $@ $< ./$(TARGET).so

$(DRIVER).o: $(DRIVER).c
	$(CC) -O0 -g -c -o $@ $< 

$(DRIVER).bc: $(DRIVER)
	$(EXTRACT_BC) -b $< -o $@

$(DRIVER)_shared.bc: $(DRIVER)_shared
	$(EXTRACT_BC) -b $< -o $@

$(DRIVER).o.bc: $(DRIVER).o
	$(EXTRACT_BC) -b $< -o $@

$(DRIVER).o.ll: $(DRIVER).o.bc
	$(LLVM_DIS) $< -o $@

$(TARGET).so: $(TARGET).o
	$(CC) -shared -fPIC -o $@ $<

$(TARGET).a: $(TARGET).o
	$(AR) rcs $@ $<

$(TARGET).o: $(TARGET).c
	$(CC) -g -O0 -c -o $@ $<


compute: $(DRIVER).bc $(DRIVER)_shared.bc
	@echo "Running condition_extractor"
# $(EXTRACTOR) $< -function $(FUNCTION) -t json -output $(TARGET).json -v v0
#	$(WPA) -steens -svfg --dump-vfg --dump-icfg -dump-callgraph ./$(TARGET).o.bc
	$(WPA) -ander --dump-icfg ./$(DRIVER).bc
	dot -Tpdf icfg_initial.dot -o icfg_svf.pdf
	$(WPA) -ander --dump-icfg ./$(DRIVER)_shared.bc
	dot -Tpdf icfg_initial.dot -o icfg_svf_shared.pdf

run: compute clean_artifacts

clean: clean_artifacts clean_exe clean_result

clean_artifacts:
	rm -f *.o *.bc *.a *.so *.ll .*.o.bc

clean_exe:
	rm -f $(DRIVER) $(DRIVER)_shared

clean_result:
	rm -f *.pdf *.dot
