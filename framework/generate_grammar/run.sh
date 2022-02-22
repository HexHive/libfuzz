#!/bin/bash

./gen_grammar.py --dependency_graph ../api_dependency/dependency_graph.json \
                --apis ../tests/simple_connection/apis.log \
                --coerce ../tests/simple_connection/coerce.log \
                --header ../tests/simple_connection/network_lib.hpp