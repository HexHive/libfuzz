#!/bin/bash

export PROJECTS=( "cpu_features" "libtiff" "minijail" "pthreadpool" "libaom" "libvpx" "libhtp" "libpcap" "c-ares" )
export NUM_OF_DRIVERS=( 20 )
export NUM_OF_APIs=( 2 4 8 16 32  )
export NUM_OF_SEEDS=1
# export POLICY="constraint_based"
export POLICY="constraint_based_weigth"
export MAX_CPUs=$(($(nproc) - 1))
export USE_CUSTOM_APIS=0

case $CONF in

  quickcamp)
    export NUM_OF_DRIVERS=( 30 ) 
    export NUM_OF_APIs=( 16 )
    export TIMEOUT=10m
    export ITERATIONS=1
    ;;

  regtest)
    export TIMEOUT=0
    ;;

  selection)
    export TIMEOUT=10m
    export ITERATIONS=1
    ;;

  long)
    export TIMEOUT=1h
    export ITERATIONS=5
    ;;

  bestconf)
    export PROJECTS=( "libaom" "libvpx" "libhtp" "libtiff" "minijail" )
    export NUM_OF_DRIVERS=( 20  )
    export NUM_OF_APIs=( 4 8  )
    export TIMEOUT=1h
    export ITERATIONS=1
    ;;

  minimized)
    export PROJECTS=( "libaom" "libvpx" "libhtp" "libtiff" )
    export NUM_OF_DRIVERS=( 20  )
    export NUM_OF_APIs=( 4 8 )
    export TIMEOUT=1h
    export ITERATIONS=1
    export USE_CUSTOM_APIS=1
    ;;

  *)
    echo -n "unknown CONF"
    exit 1
    ;;
esac