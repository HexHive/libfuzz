# My todo:

- LLVM get structures real size and log it
- make sure the driver knows their input size
    - handle strange structures such as _IO_FILE

- generate driver.cc ->
    - add a check that data size is as long as excepted


# TODO driver generation framework
- check poetry and documentation (pdoc3)
- make the framework "only for generating drivers"
- re-think shits and the role of any component

# TODO for condition_extractor:
- re-include dominator analysis (and test)
- add pointers analysis, which funcounts any field could invoke?
- run condition-extractor for each function invoked indirectly (from previos point)
- include "list of function" as parameter of condition_extractor + check the results match "single invokation"
- add false positive analysis: does any field match the original source file?
- heuristics to mark "source" and "sink" APIs

# road map

- including our custom AFL++
- add AFL++ w/  `crashmode`
- statistics from crashes 