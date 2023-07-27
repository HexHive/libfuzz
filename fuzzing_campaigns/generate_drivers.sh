#!/bin/bash

export PROJECTS=( "cpu_features" "minijail" "pthreadpool" "libtiff" )
export NUM_OF_DRIVERS=( 5 10 20 )
export NUM_OF_APIs=( 3 6 12 )

mv ../overwrite.toml ../overwrite_backup.toml
mv ../workdir ../workdir_backup 2> /dev/null

for ndrivers in "${NUM_OF_DRIVERS[@]}"; do
    for napis in "${NUM_OF_APIs[@]}"; do
        echo "[generator]" > ../overwrite.toml
        echo "pool_size = ${ndrivers}" >> ../overwrite.toml
        echo "driver_size = ${napis}" >> ../overwrite.toml
        echo "num_seeds = 20" >> ../overwrite.toml
        mkdir -p workdir_${ndrivers}_${napis}
        for project in "${PROJECTS[@]}"; do
            export TARGET=$project
            ../docker/run_drivergeneration.sh

            # Dirty way to compile all drivers
            export TIMEOUT=0s
            ../docker/run_fuzzing.sh
            mv ../workdir/${project} workdir_${ndrivers}_${napis}/${project}
        done
    done
done

mv ../overwrite_backup.toml ../overwrite.toml
mv ../workdir_backup ../workdir 2> /dev/null
