# My todo:

# ROAD MAP
- add as many libraries as possible
  - list incompatibilities, propose solutions
- fix bugs

# TODO driver generation framework
- check poetry and documentation (pdoc3)
- Special treatment for known types, such as stream objects in C++ and `FILE*`
  for standard C. (We can leverage the hooking system already present.)
- change new variable synthesis with data layout info

[MOST IMPORTANT:]
# Problems

- `htp_connp_req_data` and `htp_connp_res_data` I can't find dependencies betweeen data and len, investigate why
- source apis -> drvgen knows how to instantiate the type (basic type or user defined)
- infer which fields must be set manually? check if a struct has no WRITE access
  type for some field (and it is a complete type)

- strange function for libtiff:
  - TIFFGetConfiguredCODECs -> alwayrs return error?
  - TIFFRegisterCODEC -> memory error sometime?

# Porting to last SVF
- change include namespace and class names
- still need wllvm to compile

# TODO for condition_extractor:
- Add additional policies to recognize source APIs. Here [1], md5Init
  initializes `MD5Context`. The gist is that md5Init just writes into fields but
  does not read from any. Therefore, we can consider this as a source API
- Extend condition check with field types (the three-fields relations). See if
  it makes sense -- double check `htp_config_register_log`

- TLS_client_method (openssl) returns a global structure, this is consider a "source" function

# Stub Functions
- realloc
  - ?
x calloc
  x ret -> new object
  x par2 -> size
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