#!/bin/bash -e

source campaign_configuration.sh

IMG_NAME="libpp-clustering"
LIBPP=../

echo "[INFO] Running: $IMG_NAME"


for project in "${PROJECTS[@]}"; do
    set -x
    DOCKER_BUILDKIT=1 docker build \
        --build-arg USER_UID=$(id -u) --build-arg GROUP_UID=$(id -g) \
        --build-arg target_name="$project" \
        -t "${IMG_NAME}-${project}" --target libfuzzpp_crash_cluster \
        -f "$LIBPP/Dockerfile" "$LIBPP"
    set +x
done

      
for project in "${PROJECTS[@]}"; do
    PROJECT_FOLDER="/workspaces/libfuzz/fuzzing_campaigns/workdir_*_*/${project}"
    docker run --env TOTAL_LIBRARY_CLUSTER="YES" \
        --env TARGET_WORKDIR=${PROJECT_FOLDER} \
        -v $(pwd)/..:/workspaces/libfuzz "${IMG_NAME}-${project}"
done
