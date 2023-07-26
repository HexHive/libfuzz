#!/bin/bash

export TIMEOUT=1h
export ITERATIONS=1
export MAX_CPUs=$(($(nproc) - 1))



# ./run_analysis.sh
# ./generate_drivers.sh
./run_fuzzing.sh
