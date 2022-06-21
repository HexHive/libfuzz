#!/bin/bash -e

##
# Pre-requirements:
# - env FUZZER: fuzzer name (from fuzzers/)
# - env TARGET: target name (from targets/)
# + env MAGMA: path to magma root (default: ../../)
# + env ISAN: if set, build the benchmark with ISAN/fatal canaries (default:
#       unset)
# + env HARDEN: if set, build the benchmark with hardened canaries (default:
#       unset)
##

# if [ -z $FUZZER ] || [ -z $TARGET ] || [ -z $PROGRAM ] || [ -z $TIMEOUT ]; then
if [ -z $FUZZER ] || [ -z $TARGET ] || [ -z $TIMEOUT ]; then
    echo '$FUZZER, $TARGET, and $TIMEOUT must be specified as environment variables.'
    exit 1
fi
IMG_NAME="libpp-$TARGET"
LIBPP=../

# --build-arg program_name="$PROGRAM" \

set -x
docker build -t "$IMG_NAME" \
    --build-arg target_name="$TARGET" \
    --build-arg timeout_arg="$TIMEOUT" \
    --build-arg fuzzer_name="$FUZZER" \
    --build-arg USER_ID=$(id -u $USER) \
    --build-arg GROUP_ID=$(id -g $USER) \
    -f "$LIBPP/docker/Dockerfile" "$LIBPP"
set +x

echo "$IMG_NAME"
