#!/bin/bash -e

##
# Pre-requirements:
# - env TARGET: target name (from targets/)
##

if [ -z "$TARGET" ]; then
    echo "\$TARGET must be specified as environment variables."
    exit 1
fi

IMG_NAME="libpp-analysis"
LIBPP=../

set -x
DOCKER_BUILDKIT=1 docker build \
    --build-arg USER_UID=$(id -u) --build-arg GROUP_UID=$(id -g) \
    -t "$IMG_NAME" --target libfuzzpp_analysis \
    -f "$LIBPP/Dockerfile" "$LIBPP"
set +x

echo "$IMG_NAME"


if [[ "${DEVENV}" ]]; then
    docker run --env TARGET=${TARGET} -v "$(pwd)/..:/workspaces/libfuzz" -t "$IMG_NAME"
else
    docker run --rm -d --env TARGET=${TARGET} -v "$(pwd)/..:/workspaces/libfuzz" "$IMG_NAME"
fi
