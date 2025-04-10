#!/bin/bash

# run experiments w/o bias

../fuzzing_campaigns/fuzzing_pipeline_generation_nobias.sh

export CONF=grammar 
source ../fuzzing_campaigns/campaign_configuration.sh

FIELD_BIAS_COVERAGE=../fuzzing_campaigns/gen24_deep0/total_library_coverage_per_iter.csv
NOBIAS_COVERAGE=../fuzzing_campaigns/gen24_deep0_nobias/total_library_coverage_per_iter.csv

../tool/misc/make_table_ablation.py -f ${FIELD_BIAS_COVERAGE} -n ${NOBIAS_COVERAGE} 

rm -f config.txt