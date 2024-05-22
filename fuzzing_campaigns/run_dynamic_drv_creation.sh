#!/bin/bash

source campaign_configuration.sh

CPU_ID=0
HOST_PORT_NEW=5000

declare -A CPU_ALLOCATED
for cpu in $( eval echo {0..${MAX_CPUs}} ); do
    CPU_ALLOCATED[$cpu]="x"
done

function find_free_cpuid() {
    local i
    for i in "${!CPU_ALLOCATED[@]}"; do
        if [[ ${CPU_ALLOCATED[$i]} = "x" ]]; then
            echo $i
            exit 0
        fi
    done
    echo -1
}

function count_docker_running() {
    echo $(docker ps --format "{{.Names}}" | grep "libpp-dyndrvgen-" | wc -l)
}

for i in $( eval echo {1..$ITERATIONS} ); do
    for project in "${PROJECTS[@]}"; do
        PROJECT_FOLDER="/workspaces/libfuzz/fuzzing_campaigns/workdir_X_X/${project}"
        export TARGET=$project
        export HOST_PORT=${HOST_PORT_NEW}
        export RESULTS_FOLDER="${PROJECT_FOLDER}/iter_${i}"
        export CONTAINER_NAME="libpp-dyndrvgen-${TARGET}-${i}"

        # echo "cd: $(count_docker_running)"

        while [[ $(count_docker_running) -eq ${MAX_CPUs} ]]; do
            # echo "sleep 1m"
            sleep 1m
        done

        # free CPU ID
        for c in "${!CPU_ALLOCATED[@]}"; do
            if [ ! "$(docker ps --format \"{{.Names}}\" | grep ${CPU_ALLOCATED[$c]})" ]; then
                CPU_ALLOCATED[$c]="x"
            fi
        done

        export CPU_ID=$(find_free_cpuid)

        echo "[INFO] Allocating ${CONTAINER_NAME} to ${CPU_ID}"

        CPU_ALLOCATED[$CPU_ID]=${CONTAINER_NAME}

        ../docker/run_dyn_drivergeneration.sh

        HOST_PORT_NEW=$(( HOST_PORT_NEW + 1 ))

    done
done

echo "[INFO] Waiting for docker containers to terminate"
while [[ $(count_docker_running) -gt 0 ]]; do
    sleep 1m
done

echo "[INFO] Fuzzing campaign terminated"