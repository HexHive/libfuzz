#!/bin/bash

source campaign_configuration.sh

# This step can be done just once
./run_analysis.sh


./run_generate_drivers.sh

# Initial shorter campaign
export STABLE_DRIVERS=0
./run_fuzzing.sh && sleep $TIMEOUT_NOT_STABLE
./run_coverage.sh
./run_clustering.sh

./post_process.sh

export STABLE_DRIVERS=1
./keep_stable_drivers.sh
./run_fuzzing.sh && sleep $TIMEOUT_STABLE
./run_coverage.sh
./run_clustering.sh




