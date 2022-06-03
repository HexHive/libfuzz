# My todo:

- LLVM get structures real size and log it
- make sure the driver knows their input size
    - handle strange structures such as _IO_FILE

- generate driver.cc ->
    - add a check that data size is as long as excepted

- fuzzer session multithreading, one for generating and one for reading the feedback

- driver generation
    - handle `const` return
    - handle `void*` pointers, either return or as parameter
    - handle `handers` (function pointers) returned from APIs
    - `char*` is not `unsigned char*`
 

# road map

- make random drivers compile and test their crash (this will be funny!!)
    0. introduce incomplete types and handle the grammar
    1. lifuzz stub without input binding
    2. pseudocode into c code without input binding
    2.1 add headers
    2.1 compile without linking
    3. add the input binding