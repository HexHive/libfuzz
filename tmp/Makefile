
CXX=/usr/bin/clang++
CC=/usr/bin/clang

driver:
	$(CXX) -g -std=c++11  -fsanitize=fuzzer,address \
        driver.cc -lstdc++ -o driver

clean:
	rm -Rf driver