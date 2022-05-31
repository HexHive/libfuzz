# My todo:

- LLVM get structures real size and log it
- make sure the driver knows their input size
- generate driver.cc -> 
- map input to actual structures 
- how to include the includes? add all or only a part of? (maybe all from the include directory)
- fuzzer session multithreading, one for generating and one for reading the feedback

# road map

- make random drivers compile and test their crash (this will be funny!!)
    0. introduce incomplete types and handle the grammar
    1. lifuzz stub without input binding
    2. pseudocode into c code without input binding
    2.1 add headers
    2.1 compile without linking
    3. add the input binding