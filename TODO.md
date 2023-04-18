# My todo:

# ROAD MAP
- emit X drivers for libtiff -> compile in libfuzzer -> check how many works
- start 1h fuzzing campaing for each driver

# TODO driver generation framework
- check poetry and documentation (pdoc3)
- Special treatment for known types, such as stream objects in C++ and `FILE*`
  for standard C. (We can leverage the hooking system already present.)
- change new variable synthesis with data layout info
- add a flag (?) to avoid rebuild docker in `docker/` scripts
- restructur `workdir` and add separate folder for compiled drivers and generated corpus? 
- keep a copy of the inital corpus? or a backup of driver+corpus somewhere before fuzzing?
- different source API algorithm:
  - A) if the library assumes *incomplete* types
  - B) if the library assumes *all-complete* types

[MOST IMPORTANT:]
- fix custom mutator: 
  - remove `custom_mutator_ok` global variable
  - return seed length 0 if mutation invalid
  - driver exists if length 0
  - no need any global variable!!
- the corpus has seeds with 0 size: why?!?!
- if allocating a buffer of pointer to structures, better reasoning if we need
  HEAP or STACK allocation, happens with TIFF and uriparser. Try to understand
  what's goning on
- TIFFWarning with NULL as second arg, why? it is a string, should be not NULL
- TIFFUnRegisterCODEC(TIFFCodec) should be initialized, it is not incomplete
```
typedef int (*TIFFInitMethod)(TIFF*, int);
typedef struct {
	char* name;
	uint16_t scheme;
	TIFFInitMethod init;
} TIFFCodec;
```

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