#!/bin/bash

export CONF=quickcamp; ./run_analysis.sh

function store_results_to() {
    DEST_FOLDER=$1

    mkdir ${DEST_FOLDER}
    mv workdir_* ${DEST_FOLDER}
    mv config.txt ${DEST_FOLDER}
    mv total_library_coverage* ${DEST_FOLDER}
    if [ -f "time_budget.csv" ]
    then
        mv time_budget.csv ${DEST_FOLDER}
    fi
}

GEN24_DEEP0=gen24_deep0_nobias
# GEN18_DEEP6=gen18_deep6
# GEN12_DEEP12=gen12_deep12
# GEN6_DEEP18=gen6_deep18

# dyn generation for 24 hours and no deep
export CONF=grammar_quick_nobias; ./run_dynamic_drv_creation.py; ./run_coverage.sh; ./get_total_library_coverage.sh;
store_results_to ${GEN24_DEEP0}

# # select best drivers from 18h and deep for 6h
# export CONF=grammar; ./select_stable_drivers_cluster.py -d ${GEN24_DEEP0} -t 18h -k
# export CONF=grammar; ./run_dynamic_drv_deep.py; ./run_coverage.sh
# export CONF=grammar; ./cp_coverage_from_generation_phase.py -d ${GEN24_DEEP0} -t 18h
# export CONF=grammar; ./run_coverage.sh recalciter; ./get_total_library_coverage.sh; 
# store_results_to ${GEN18_DEEP6}

# # select best drivers from 12h and deep for 12h
# export CONF=grammar; ./select_stable_drivers_cluster.py -d ${GEN24_DEEP0} -t 12h -k
# export CONF=grammar; ./run_dynamic_drv_deep.py; ./run_coverage.sh
# export CONF=grammar; ./cp_coverage_from_generation_phase.py -d ${GEN24_DEEP0} -t 12h
# export CONF=grammar; ./run_coverage.sh recalciter; ./get_total_library_coverage.sh; 
# store_results_to ${GEN12_DEEP12}

# # select best drivers from 6h and deep for 18h
# export CONF=grammar; ./select_stable_drivers_cluster.py -d ${GEN24_DEEP0} -t 6h -k
# export CONF=grammar; ./run_dynamic_drv_deep.py; ./run_coverage.sh
# export CONF=grammar; ./cp_coverage_from_generation_phase.py -d ${GEN24_DEEP0} -t 6h
# export CONF=grammar; ./run_coverage.sh recalciter; ./get_total_library_coverage.sh; 
# store_results_to ${GEN6_DEEP18}
