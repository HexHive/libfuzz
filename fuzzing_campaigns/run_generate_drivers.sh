#!/bin/bash

source campaign_configuration.sh

mv ../overwrite.toml ../overwrite_backup.toml
mv ../workdir ../workdir_backup 2> /dev/null

for ndrivers in "${NUM_OF_DRIVERS[@]}"; do
    for napis in "${NUM_OF_APIs[@]}"; do
        echo "[generator]" > ../overwrite.toml
        echo "pool_size = ${ndrivers}" >> ../overwrite.toml
        echo "driver_size = ${napis}" >> ../overwrite.toml
        echo "num_seeds = ${NUM_OF_SEEDS}" >> ../overwrite.toml
        echo "policy = \"${POLICY}\"" >> ../overwrite.toml
        mkdir -p workdir_${ndrivers}_${napis}
        for project in "${PROJECTS[@]}"; do
            export TARGET=$project
            ../docker/run_drivergeneration.sh

            # Dirty way to compile all drivers
            export TIMEOUT=0s
            ../docker/run_fuzzing.sh
            rm -Rf workdir_${ndrivers}_${napis}/${project} || true
            mv ../workdir/${project} workdir_${ndrivers}_${napis}/${project}
        done
    done
done

mv ../overwrite_backup.toml ../overwrite.toml
mv ../workdir_backup ../workdir 2> /dev/null
