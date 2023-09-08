#!/bin/bash

export PROJECTS=( "pthreadpool" "libhtp" )
export NUM_OF_DRIVERS=( 20 )
export NUM_OF_APIs=( 2 4 8 16 32  )
export NUM_OF_SEEDS=20
# export POLICY="constraint_based"
export POLICY="constraint_based_weigth"
export TIMEOUT=10m
export ITERATIONS=1
export MAX_CPUs=$(($(nproc) - 1))
