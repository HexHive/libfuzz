#!/bin/bash

source campaign_configuration.sh

rm results.csv || true
touch results.csv

echo "Project,Driver,# Drivers,# APIs,Iteration,Coverage,Total Cov,Crash,Unique Crash" > results.csv

for ndrivers in "${NUM_OF_DRIVERS[@]}"; do
    for napis in "${NUM_OF_APIs[@]}"; do
        for i in $( eval echo {1..$ITERATIONS} ); do
            for project in "${PROJECTS[@]}"; do
                PROJECT_FOLDER="./workdir_${ndrivers}_${napis}/${project}"
                DRIVER_FOLDER="${PROJECT_FOLDER}/drivers"
                RESULTS_FOLDER="${PROJECT_FOLDER}/results/iter_${i}"
                FUZZ_TARGETS="$(find ${DRIVER_FOLDER} -maxdepth 1 -type f -executable -printf '%P\n')"
                LIBRARY_COVERAGE_REPORT="./workdir_${ndrivers}_${napis}/${project}/coverage_data/iter_${i}/report"
                total_coverage=$(tail -n 1 $LIBRARY_COVERAGE_REPORT | awk '{print $4}')
                for fuzz_target in $FUZZ_TARGETS; do
                    CRASHES_DIR=${RESULTS_FOLDER}/crashes/${fuzz_target}
                    UNIQUE_CRASHES_DIR=${PROJECT_FOLDER}/clusters/${fuzz_target}
                    COVERAGE_REPORT="./workdir_${ndrivers}_${napis}/${project}/coverage_data/iter_${i}/${fuzz_target}/report"
                    coverage=$(tail -n 1 $COVERAGE_REPORT | awk '{print $4}')
                    total_crashes=$(ls $CRASHES_DIR | wc -l)
                    unique_crashes=$(ls $UNIQUE_CRASHES_DIR | wc -l)
                    echo "${project},${fuzz_target},${ndrivers},${napis},${i},${coverage},${total_coverage},${total_crashes},${unique_crashes}" >> results.csv
                done
            done
        done
    done
done
