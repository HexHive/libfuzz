#!/bin/bash -e

source campaign_configuration.sh

IMG_NAME="libpp-coverage"
LIBPP=../

echo "[INFO] Running: $IMG_NAME"

CPU_ID=0
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
    echo $(docker ps --format "{{.Names}}" | grep "${IMG_NAME}-" | wc -l)
}

for project in "${PROJECTS[@]}"; do
    set -x
    DOCKER_BUILDKIT=1 docker build \
        --build-arg USER_UID=$(id -u) --build-arg GROUP_UID=$(id -g) \
        --build-arg target_name="$project" \
        -t "${IMG_NAME}-${project}" --target libfuzzpp_coverage \
        -f "$LIBPP/Dockerfile" "$LIBPP"
    set +x
done

COV_ID=0
for project in "${PROJECTS[@]}"; do
    for ndrivers in "${NUM_OF_DRIVERS[@]}"; do
        for napis in "${NUM_OF_APIs[@]}"; do
            for i in $( eval echo {1..$ITERATIONS} ); do

                    PROJECT_FOLDER="/workspaces/libfuzz/fuzzing_campaigns/workdir_${ndrivers}_${napis}/${project}"

                    if [[ -z ${GRAMMAR_MODE} ]]; then
                        DRIVER_FOLDER="${PROJECT_FOLDER}/drivers"
                        CORPUS_FOLDER="${PROJECT_FOLDER}/results/iter_${i}/corpus_new"
                        COVERAGE_FOLDER="${PROJECT_FOLDER}/coverage_data/iter_${i}"
                    else
                        DRIVER_FOLDER="${PROJECT_FOLDER}/iter_${i}/drivers"
                        CORPUS_FOLDER="${PROJECT_FOLDER}/iter_${i}/corpus_new"
                        COVERAGE_FOLDER="${PROJECT_FOLDER}/iter_${i}/coverage_data"
                    fi

                    export CONTAINER_NAME="${IMG_NAME}-${project}-${COV_ID}"

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

                    docker run -d --rm --cpuset-cpus ${CPU_ID} \
                        --name ${CONTAINER_NAME} \
                        --env DRIVER_FOLDER=${DRIVER_FOLDER} \
                        --env PROJECT_COVERAGE=${COVERAGE_FOLDER} \
                        --env TARGET=${project} \
                        --env CORPUS_FOLDER=${CORPUS_FOLDER} \
                        --env GRAMMAR_MODE=${GRAMMAR_MODE} \
                        --env TOTAL_DRIVER_COVERAGE_COMULATIVE=1 \
                        -v $(pwd)/..:/workspaces/libfuzz \
                        --mount type=tmpfs,destination=/tmpfs \
                        "${IMG_NAME}-${project}"

                    COV_ID=$(( COV_ID + 1))

            done
        done
    done
done

echo "[INFO] Waiting for docker containers to terminate"
while [[ $(count_docker_running) -gt 0 ]]; do
    sleep 1m
done

echo "[INFO] Coverage collection terminated"
