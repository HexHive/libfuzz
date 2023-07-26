#!/bin/bash

export PROJECTS=( "cpu_features" "minijail" "pthreadpool" "libtiff" )
export NUM_OF_DRIVERS=( 5 10 20 )
export NUM_OF_APIs=( 3 6 12 )

for project in "${PROJECTS[@]}"; do
    export TARGET=$project
    ../docker/run_analysis.sh
done
