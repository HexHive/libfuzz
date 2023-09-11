#!/bin/bash

export CONF=long
source campaign_configuration.sh

./run_fuzzing.sh
./run_coverage.sh
./run_clustering.sh

./post_process
./get_total_library_coverage.sh




