# My todo:


# TODO driver generation framework
- check poetry and documentation (pdoc3)
- Include other  forms of argument dependency, e,g,, memcpy , strcpy, and other
  functions like that, check below: b depends on len_b since used by memcpy. (We
  can leverage the hooking system already present.)
```
void set_data(my_struct *s, char *b, size_t len_b)  {
	if (s->generic_data != NULL)
		free(s->generic_data);
	s->generic_data = (char*) malloc(len_b);
	memcpy(s->generic_data, b, len_b);
}
```
- Special treatment for known types, such as stream objects in C++ and `FILE*`
  for standard C. (We can leverage the hooking system already present.)

# TODO for condition_extractor:
- Add additional policies to recognize source APIs. Here [1], md5Init
  initializes `MD5Context`. The gist is that md5Init just writes into fields but
  does not read from any. Therefore, we can consider this as a source API
- differentiate between buffers in stack and heap! now I really need it :S. Here, I should add a boolean (stack/heap?) and then use this information in the backend. How, I only rely on `is_incomplete`, which is not sufficient.
- In `try_to_instantiate_api_call`, I should add a test to understand if the
  condition of a variable allows me to instantiate a new variable from skretch (otherwise `raise Unsat()`)
- Include custom mutator in libfuzzer to handle dynamic arrays
- Extend condition check with field types (the three-fields relations). See if
  it makes sense

# road map

- implement stack/heap
- remove null pointer in driver creation
- emit X drivers for libtiff -> compile in libfuzzer -> check how many works
- start 1h fuzzing campaing for each driver

# Links
[1] https://github.com/Zunawe/md5-c/blob/main/md5.h