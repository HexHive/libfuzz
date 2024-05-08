#!/bin/bash

if [ -z $TARGET ]; then
    echo '$TARGET must be specified as environment variables.'
    exit 1
fi

TIMEOUT=1m
DRIVER_TIMEOUT=10s

IMG_NAME="libpp-dyndrvgen-$TARGET"
LIBPP=../

set -x
DOCKER_BUILDKIT=1 docker build \
    --build-arg USER_UID=$(id -u) --build-arg GROUP_UID=$(id -g) \
    --build-arg target_name="$TARGET" \
    -t "$IMG_NAME" --target libfuzzpp_dyndrvgen \
    -f "$LIBPP/Dockerfile" "$LIBPP"
set +x

echo "[INFO] Running: $IMG_NAME"

docker run --env DRIVER=${DRIVER} --env WHOLE_TIMEOUT=${TIMEOUT} \
    --env TIMEOUT=${DRIVER_TIMEOUT} -v $(pwd)/..:/workspaces/libfuzz $IMG_NAME