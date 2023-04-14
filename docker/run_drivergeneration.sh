#!/bin/bash -e

##
# Pre-requirements:
# - env TARGET: target name (from targets/)
##

if [ -z $TARGET ]; then
    echo '$TARGET must be specified as environment variables.'
    exit 1
fi

IMG_NAME="libpp-drvgen-$TARGET"
LIBPP=../

set -x
docker build -t "$IMG_NAME" \
    --target libfuzzpp_drivergeneration \
    --build-arg target_name="$TARGET" \
    -f "$LIBPP/Dockerfile" "$LIBPP"
set +x

echo "$IMG_NAME"

docker run -v $(pwd)/..:/workspaces/libfuzz $IMG_NAME
