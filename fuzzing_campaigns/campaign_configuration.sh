#!/bin/bash

export PROJECTS=( "cpu_features" "minijail" "pthreadpool" "libhtp" "libvpx" "libtiff" )
export NUM_OF_DRIVERS=( 5 10 20 )
export NUM_OF_APIs=( 3 6 12 )
export NUM_OF_SEEDS=20
export POLICY="constraint_based"
# export POLICY="constraint_based_weigth"
export TIMEOUT_NOT_STABLE=10m
export TIMEOUT_STABLE=1h
export ITERATIONS=5
export MAX_CPUs=$(($(nproc) - 1))
