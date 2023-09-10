#!/bin/bash -e

source campaign_configuration.sh

IMG_NAME="libpp-coverage"
LIBPP=../

echo "[INFO] Running: $IMG_NAME"


for project in "${PROJECTS[@]}"; do
    set -x
    DOCKER_BUILDKIT=1 docker build \
        --build-arg USER_UID=$(id -u) --build-arg GROUP_UID=$(id -g) \
        --build-arg target_name="$project" \
        -t "${IMG_NAME}-${project}" --target libfuzzpp_coverage \
        -f "$LIBPP/Dockerfile" "$LIBPP"
    set +x
done

for project in "${PROJECTS[@]}"; do
    for ndrivers in "${NUM_OF_DRIVERS[@]}"; do
        for napis in "${NUM_OF_APIs[@]}"; do
            for i in $( eval echo {1..$ITERATIONS} ); do
                    PROJECT_FOLDER="/workspaces/libfuzz/fuzzing_campaigns/workdir_${ndrivers}_${napis}/${project}"
                    DRIVER_FOLDER="${PROJECT_FOLDER}/drivers"
                    CORPUS_FOLDER="${PROJECT_FOLDER}/results/iter_${i}/corpus_new"
                    COVERAGE_FOLDER="/workspaces/libfuzz/fuzzing_campaigns/workdir_${ndrivers}_${napis}/${project}/coverage_data/iter_${i}"
                    docker run --env DRIVER_FOLDER=${DRIVER_FOLDER} --env PROJECT_COVERAGE=${COVERAGE_FOLDER} --env TARGET=${project} --env CORPUS_FOLDER=${CORPUS_FOLDER} \
                        -v $(pwd)/..:/workspaces/libfuzz "${IMG_NAME}-${project}"

            done
        done
    done
done

rm ../crash-*
rm ../oom-*
rm ../*.bin
