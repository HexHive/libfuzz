#!/bin/bash

export PROJECTS=( "cpu_features" "libtiff" "minijail" "pthreadpool" "libaom" "libvpx" "libhtp" "libpcap" "c-ares" "zlib" "cjson" )
export NUM_OF_DRIVERS=( 40 )
export NUM_OF_APIs=( 2 4 8 16 32  )
export NUM_OF_SEEDS=1
# export POLICY="constraint_based"
export POLICY="constraint_based_weigth"
export MAX_CPUs=$(($(nproc) - 1))
export USE_CUSTOM_APIS=0

case $CONF in

  quickcamp)
    export NUM_OF_DRIVERS=( 20 ) 
    export NUM_OF_APIs=( 5 )
    export TIMEOUT=10m
    export ITERATIONS=1
    ;;

  regtest)
    export TIMEOUT=0
    ;;

  selection)
    export TIMEOUT=5m
    export ITERATIONS=1
    ;;

  long)
    export USE_PER_LIBRARY_TIMEBUDGET=1
    export ITERATIONS=1
    ;;

  bestconf)
    export PROJECTS=( "libaom" "libvpx" "libhtp" "libtiff" "minijail" )
    export NUM_OF_DRIVERS=( 20  )
    export NUM_OF_APIs=( 4 8  )
    export TIMEOUT=1h
    export ITERATIONS=1
    ;;

  minimized)
    export PROJECTS=( "libaom" "libvpx" "libhtp" "libtiff" "libpcap" "c-ares" "zlib" "cjson" )
    # probably we can fix the number of drivers to match 24 hours
    export NUM_OF_DRIVERS=( 20  )
    export NUM_OF_APIs=( 4 8 )
    export TIMEOUT=30m
    export ITERATIONS=1
    export USE_CUSTOM_APIS=1
    ;;

  *)
    echo -n "unknown CONF"
    exit 1
    ;;
esac

# LOG the configuration
LOG_FILE=config.txt
date >> $LOG_FILE
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
echo "$SCRIPTPATH/$0" >> $LOG_FILE
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' - >> $LOG_FILE
env >> $LOG_FILE
