#!/bin/bash

export PROJECTS=( "cpu_features" "minijail" "pthreadpool" "libtiff" )
export NUM_OF_DRIVERS=( 5 10 20 )
export NUM_OF_APIs=( 3 6 12 )
export TIMEOUT=5s
export ITERATIONS=5
export MAX_CPUs=$(($(nproc) - 1))
