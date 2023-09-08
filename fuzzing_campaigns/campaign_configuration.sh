#!/bin/bash

export PROJECTS=( "cpu_features" "libtiff" "minijail" "pthreadpool" "libaom" "libvpx" "libhtp" )
export NUM_OF_DRIVERS=( 20 )
export NUM_OF_APIs=( 2 4 8 16 32  )
export NUM_OF_SEEDS=20
# export POLICY="constraint_based"
export POLICY="constraint_based_weigth"
export TIMEOUT_NOT_STABLE=10m
export TIMEOUT_STABLE=1h
export ITERATIONS=5
export MAX_CPUs=$(($(nproc) - 1))
