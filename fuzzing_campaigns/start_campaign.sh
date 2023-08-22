#!/bin/bash

source campaign_configuration.sh

# ./run_analysis.sh
./run_generate_drivers.sh
./run_fuzzing.sh

sleep $TIMEOUT
./run_coverage.sh
