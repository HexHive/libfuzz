#!/bin/bash

./gen_driver.py --grammar ../generate_grammar/grammar.json \
                --apis ../tests/simple_connection/apis.log \
                --coerce ../tests/simple_connection/coerce.log \
                --header ../tests/simple_connection/network_lib.hpp