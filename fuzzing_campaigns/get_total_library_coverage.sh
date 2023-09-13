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

rm total_library_coverage.csv || true
touch total_library_coverage.csv

for project in "${PROJECTS[@]}"; do
    docker run --env TOTAL_LIBRARY_COVERAGE="YES" -v $(pwd)/..:/workspaces/libfuzz "${IMG_NAME}-${project}"
    LIBRARY_COVERAGE_REPORT="./total_library_coverage/${project}/report"
    total_coverage=$(tail -n 1 $LIBRARY_COVERAGE_REPORT | awk '{print $13}')
    echo "${project},${total_coverage}" >> total_library_coverage.csv
done
