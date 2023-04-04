# My todo:

# ROAD MAP
- emit X drivers for libtiff -> compile in libfuzzer -> check how many works
- start 1h fuzzing campaing for each driver

# TODO driver generation framework
- check poetry and documentation (pdoc3)
- Special treatment for known types, such as stream objects in C++ and `FILE*`
  for standard C. (We can leverage the hooking system already present.)

- if only fix seeds -> the corpus has seeds with 0 size!

- if return pointers to TIFFTagMethods (or struct in general), I have to put the buffer in heap

- include hash types in DataLayout (in gen driver) and find how to synthetize new access type

# TODO for condition_extractor:
- Add additional policies to recognize source APIs. Here [1], md5Init
  initializes `MD5Context`. The gist is that md5Init just writes into fields but
  does not read from any. Therefore, we can consider this as a source API
- In `try_to_instantiate_api_call`, I should add a test to understand if the
  condition of a variable allows me to instantiate a new variable from skretch (otherwise `raise Unsat()`)
- Extend condition check with field types (the three-fields relations). See if
  it makes sense

- TLS_client_method (openssl) returns a global structure, this is consider a "source" function

# Stub Functions
- realloc
  - ?
- calloc
  - ?
- <other malloc-like function?>
x malloc
  x ret -> allocate new object/buffer
x memcpy
  x par0 -> is array;
  x par1 -> is array; depends on par2
x memset
  x par0 -> is array; depends on par2
x strlen
  x par0 -> is array; is string (?)
x strcpy
  xpar0 -> is array; is string (?)
  x par1 -> is array; is string (?)
x open/fopen
  x par0 -> is file path
x free
  x par0 -> (delete, [], void*)

# Links

[1] https://github.com/Zunawe/md5-c/blob/main/md5.h