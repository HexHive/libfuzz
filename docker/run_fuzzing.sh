#!/bin/bash -e

##
# Pre-requirements:
# - env TARGET: target name (from targets/)
##

if [ -z $TARGET ] || [ -z $TIMEOUT ]; then
    echo '$TARGET, and $TIMEOUT must be specified as environment variables.'
    exit 1
fi

# if DRIVER unset, we consider all the driver.cc in the folder
if [ -z $DRIVER ]; then
    echo "[INFO] DRIVER unset, selecting all the driver.cc produced"
    DRIVER="*" 
fi

IMG_NAME="libpp-fuzzing-$TARGET"
LIBPP=../

set -x
DOCKER_BUILDKIT=1 docker build \
    --build-arg USER_UID=$(id -u) --build-arg GROUP_UID=$(id -g) \
    --build-arg target_name="$TARGET" \
    -t "$IMG_NAME" --target libfuzzpp_fuzzing \
    -f "$LIBPP/Dockerfile" "$LIBPP"
set +x

echo "[INFO] Running: $IMG_NAME"

docker run --env DRIVER=${DRIVER} --env TIMEOUT=${TIMEOUT} \
    -v $(pwd)/..:/workspaces/libfuzz $IMG_NAME
