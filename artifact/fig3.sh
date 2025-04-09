#!/bin/bash
# This script is used to generate Figure 3 and Table 4 in the paper.

export ITERATIONS=1
export TIMEOUT=4h
cd ./fuzzing_campaigns
./fuzzing_pipeline_generation.sh
