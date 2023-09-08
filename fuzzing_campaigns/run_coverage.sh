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


for ndrivers in "${NUM_OF_DRIVERS[@]}"; do
    for napis in "${NUM_OF_APIs[@]}"; do
        for project in "${PROJECTS[@]}"; do
            PROJECT_FOLDER="/workspaces/libfuzz/fuzzing_campaigns/workdir_${ndrivers}_${napis}/${project}"
            # for i in $( eval echo {1..$ITERATIONS} ); do
            #     DRIVER_FOLDER="${PROJECT_FOLDER}/drivers"
            #     CORPUS_FOLDER="${PROJECT_FOLDER}/results/iter_${i}/corpus_new"
            #     COVERAGE_FOLDER="/workspaces/libfuzz/fuzzing_campaigns/workdir_${ndrivers}_${napis}/${project}/coverage_data/iter_${i}"
            #     docker run --env DRIVER_FOLDER=${DRIVER_FOLDER} --env PROJECT_COVERAGE=${COVERAGE_FOLDER} --env TARGET=${project} --env CORPUS_FOLDER=${CORPUS_FOLDER} \
            #         -v $(pwd)/..:/workspaces/libfuzz "${IMG_NAME}-${project}"
            # done
            # docker run --env TOTAL_DRIVER_COVERAGE="YES" --env PROJECT_FOLDER=${PROJECT_FOLDER} -v $(pwd)/..:/workspaces/libfuzz "${IMG_NAME}-${project}"
            docker run --env TOTAL_LIBRARY_COVERAGE_FOR_CONFIGURATION="YES" --env PROJECT_FOLDER=${PROJECT_FOLDER} -v $(pwd)/..:/workspaces/libfuzz "${IMG_NAME}-${project}"
        done
    done
done


rm total_library_coverage.csv || true
touch total_library_coverage.csv

for project in "${PROJECTS[@]}"; do
    docker run --env TOTAL_LIBRARY_COVERAGE="YES" -v $(pwd)/..:/workspaces/libfuzz "${IMG_NAME}-${project}"
    LIBRARY_COVERAGE_REPORT="./total_library_coverage/${project}/report"
    total_coverage=$(tail -n 1 $LIBRARY_COVERAGE_REPORT | awk '{print $4}')
    echo "${project},${total_coverage}" >> total_library_coverage.csv
done


rm ../crash-*
rm ../oom-*
rm ../*.bin
