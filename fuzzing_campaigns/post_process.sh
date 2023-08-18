#!/bin/bash

source campaign_configuration.sh

rm results_coverage_crash || true
touch results_coverage_crash

# TODO: ADD ORIGINAL FOLDER (E.G., NUM API AND NUM DRIVER)
fmt="%-20s%-12s%-12s%-12s%-12s%-12s\n"
# HEADER COLUMN
printf "$fmt" "Project" "Driver" "Iteration" "Coverage" "Crash" "Unique Crash" > results_coverage_crash

for ndrivers in "${NUM_OF_DRIVERS[@]}"; do
    for napis in "${NUM_OF_APIs[@]}"; do
        for i in $( eval echo {1..$ITERATIONS} ); do
            for project in "${PROJECTS[@]}"; do
                PROJECT_FOLDER="./workdir_${ndrivers}_${napis}/${project}"
                DRIVER_FOLDER="${PROJECT_FOLDER}/drivers"
                RESULTS_FOLDER="${PROJECT_FOLDER}/results/iter_${i}"
                FUZZ_TARGETS="$(find ${DRIVER_FOLDER} -maxdepth 1 -type f -executable -printf '%P\n')"
                for fuzz_target in $FUZZ_TARGETS; do
                    CRASHES_DIR=${RESULTS_FOLDER}/crashes/${fuzz_target}
                    UNIQUE_CRASHES_DIR=${PROJECT_FOLDER}/clusters/${fuzz_target}
                    COVERAGE_REPORT="./workdir_${ndrivers}_${napis}/${project}/coverage_data/iter_${i}/${fuzz_target}/report"
                    coverage=$(tail -n 1 $COVERAGE_REPORT | awk '{print $4}')
                    total_crashes=$(ls $CRASHES_DIR | wc -l)
                    unique_crashes=$(ls $UNIQUE_CRASHES_DIR | wc -l)

                    # echo "${project} ${fuzz_target} ${total_crashes} ${unique_crashes}"
                    printf "$fmt" ${project} ${fuzz_target} ${i} ${coverage} ${total_crashes} ${unique_crashes} >> results_coverage_crash
                    # echo -n $(tail -n 1 $COVERAGE_REPORT | awk '{print $4}') >> results_coverage_crash
                    # echo -n "     " >> results_coverage_crash
                    # ls $CRASHES_DIR | wc -l >> results_coverage_crash
                done
            done
        done
    done
done
