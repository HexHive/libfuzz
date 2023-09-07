#!/bin/bash

export PROJECTS=( "cpu_features" "minijail" "pthreadpool" "libhtp" "libvpx" "libtiff" "libaom" )
export NUM_OF_DRIVERS=( 5 10 20 )
export NUM_OF_APIs=( 3 6 12 )
export NUM_OF_SEEDS=20
# export POLICY="constraint_based"
export POLICY="constraint_based_weigth"
export TIMEOUT=5m
export ITERATIONS=1
export MAX_CPUs=$(($(nproc) - 1))
