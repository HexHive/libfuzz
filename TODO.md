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

[MOST IMPORTANT:]
- TIFFWarning with NULL as second arg, why? it is a string, should be not NULL
- add headers allow-list in `extract_included_functions.py` and `.toml`
  configuraiton file || maybe remove/move non public headers fater analysis.sh/build_library.sh?
- in dynamic array chars, include a check that len(array) > 0 before setting array[len-1] = 0
- `htp_connp_req_data` and `htp_connp_res_data` I can't find dependencies betweeen data and len, investigate why

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