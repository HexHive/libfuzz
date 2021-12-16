CC=/workspace/libfuzz/LLVM/build/bin/clang
CXX=/workspace/libfuzz/LLVM/build/bin/clang++

LIB_LIBRARY=lib

TARGET_CLIENT=myClient
TARGET_LIB=myLib

all: $(TARGET_LIB).so $(TARGET_CLIENT)
	echo "done!"

$(TARGET_LIB).so: $(TARGET_LIB).cpp $(TARGET_LIB).hpp
	mkdir -p $(LIB_LIBRARY)
	$(CXX) -mllvm -get-api-pass -fPIC -c -o $(TARGET_LIB).o $<
	$(CXX) -shared -o $(LIB_LIBRARY)/lib$@ $(TARGET_LIB).o

$(TARGET_CLIENT): $(TARGET_CLIENT).cpp
	$(CXX) -L$(LIB_LIBRARY) -Wall -o $@ $< -l$(TARGET_LIB)

clean:
	rm -Rf $(LIB_LIBRARY)
	rm $(TARGET_CLIENT) $(TARGET_LIB).o

run:
	@LD_LIBRARY_PATH=./$(LIB_LIBRARY):$(LD_LIBRARY_PATH) ./$(TARGET_CLIENT)