#!/bin/bash

if [ -z $TARGET ]; then
    echo '$TARGET must be specified as environment variables.'
    exit 1
fi

if [ -z $TIMEOUT ]; then
    TIMEOUT=12h
fi

if [ -z $HOST_PORT ]; then
    HOST_PORT=5000
fi

DRIVER_TIMEOUT=5m

IMG_NAME="libpp-dyndrvgen-$TARGET"
LIBPP=../

# # FLAVIO: this block makes sure to recompile LLVM and make it available for the next script
#set -x
#DOCKER_BUILDKIT=1 docker build --build-arg USER_UID=$(id -u) \
#    --build-arg GROUP_UID=$(id -g) --target libfuzzpp_dev_image \
#    -t libfuzzpp_dev_image -f "$LIBPP/Dockerfile" "$LIBPP"
#docker run -v $(pwd)/..:/workspaces/libfuzz libfuzzpp_dev_image /workspaces/libfuzz/llvm-project/build.sh
# set +x

set -x
DOCKER_BUILDKIT=1 docker build \
    --build-arg USER_UID=$(id -u) --build-arg GROUP_UID=$(id -g) \
    --build-arg target_name="$TARGET" \
    -t "$IMG_NAME" --target libfuzzpp_dyndrvgen \
    -f "$LIBPP/Dockerfile" "$LIBPP"
set +x

echo "[INFO] Running: $IMG_NAME"
docker run -p ${HOST_PORT}:5000 --rm --env DRIVER=${DRIVER} --env WHOLE_TIMEOUT=${TIMEOUT} \
    --env TIMEOUT=${DRIVER_TIMEOUT} -v $(pwd)/..:/workspaces/libfuzz $IMG_NAME
