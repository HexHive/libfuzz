#!/bin/bash


# Initial shorter campaign
export CONF=selection
source campaign_configuration.sh


./run_fuzzing.sh
./run_coverage.sh
# ./run_clustering.sh

./post_process.sh
./select_stable_drivers.py -r results.csv -d $(pwd)




