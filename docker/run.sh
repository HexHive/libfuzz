#!/bin/bash

# --env BUILD_AND_RUN=1 \

if [ -z $PROGRAM ] || [ -z $IMAGE ]; then
    echo '$PROGRAM and $IMAGE must be specified as environment variables.'
    exit 1
fi

docker run \
    -v /workspace/libfuzz/workdir/reports/:/libfuzzpp_shared/findings/ \
    -v /workspace/libfuzz/workdir/drivers/:/libfuzzpp_shared/drivers/ \
    -v /workspace/libfuzz/workdir/corpus/:/libfuzzpp_shared/corpus/ \
    --env PROGRAM=$PROGRAM \
    --env BUILD_AND_RUN=1 \
    $IMAGE

# docker run -v /workspace/libfuzz/workdir/reports/:/libfuzzpp_shared/findings/ -v /workspace/libfuzz/workdir/drivers/:/libfuzzpp_shared/drivers/ -v /workspace/libfuzz/workdir/corpus/:/libfuzzpp_shared/corpus/ -it --entrypoint /bin/bash libpp-libtiff 