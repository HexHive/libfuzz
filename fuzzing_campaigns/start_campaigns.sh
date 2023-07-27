#!/bin/bash


# ./run_analysis.sh
# ./generate_drivers.sh

export TIMEOUT=1h
export ITERATIONS=1
export MAX_CPUs=$(($(nproc) - 1))
./run_fuzzing.sh
