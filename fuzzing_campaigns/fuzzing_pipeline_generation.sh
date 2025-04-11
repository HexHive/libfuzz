#!/bin/bash

if [ -z "$1" ]; then
  CONFIG_NAME="grammar"
else
  CONFIG_NAME=$1
fi

if [ "$2" ]; then
  ONLY_GENERATION=1
fi

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

if [ "${ONLY_GENERATION}"]; then
    ONLY_GEN=gen24_deep0_nobias
else
    ONLY_GEN=gen24_deep0
fi


# dyn generation for 24 hours and no deep
export CONF=${CONFIG_NAME};
source campaign_configuration.sh
echo "TIMEOUT=${TIMEOUT}"
UNIT=${TIMEOUT: -1}
TIMEOUT_NO_UNIT=${TIMEOUT::-1}
ONLY_GEN=gen${TIMEOUT_NO_UNIT}_deep0

./run_dynamic_drv_creation.py; ./run_coverage.sh; ./run_coverage.sh comulative; ./get_total_library_coverage.sh;
store_results_to ${ONLY_GEN}

# From the number of interval and the TIMEOUT value, create the campaigns names
for (( i=0; i<${INTERVAL}; i++ ))
do
    echo "STEP iteration: ${i}"
    # Calculate the start and end time for each interval
    RATIO=$(awk "BEGIN { print (${i}+1) * 1/(${INTERVAL}+1)}")
    TTEST=$(awk "BEGIN { print (${i}+1) * 1/(${INTERVAL}+1) * ${TIMEOUT_NO_UNIT}}")
    TGEN=$(awk "BEGIN { print (1-(${i}+1) * 1/(${INTERVAL}+1)) * ${TIMEOUT_NO_UNIT}}")

    # Create the campaign name
    CAMPAIGN_NAME="gen${TGEN}_deep${TTEST}"
    
    # Print the campaign name
    echo "Campaign name: ${CAMPAIGN_NAME}"
    export CONF=${CONFIG_NAME}; ./select_stable_drivers_cluster.py -d ${ONLY_GEN} -t ${RATIO} -k
    export CONF=${CONFIG_NAME}; ./run_dynamic_drv_deep.py; ./run_coverage.sh
    export CONF=${CONFIG_NAME}; ./cp_coverage_from_generation_phase.py -d ${ONLY_GEN} -t ${RATIO}
    export CONF=${CONFIG_NAME}; ./run_coverage.sh recalciter; ./get_total_library_coverage.sh; 
    store_results_to ${CAMPAIGN_NAME}
done
