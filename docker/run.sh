#!/bin/bash

if [ -z $PROGRAM ] || [ -z $IMAGE ] || [ -z $MODE ]; then
    echo '$PROGRAM, $IMAGE, and $MODE must be specified as environment variables.'
    exit 1
fi

# MODE = { build | run | build+run }

docker run \
    -v /workspace/libfuzz/workdir/reports/:/libfuzzpp_shared/findings/ \
    -v /workspace/libfuzz/workdir/drivers/:/libfuzzpp_shared/drivers/ \
    -v /workspace/libfuzz/workdir/corpus/:/libfuzzpp_shared/corpus/ \
    --env PROGRAM=$PROGRAM \
    --env MODE=$MODE \
    $IMAGE

# docker run -v /workspace/libfuzz/workdir/reports/:/libfuzzpp_shared/findings/ -v /workspace/libfuzz/workdir/drivers/:/libfuzzpp_shared/drivers/ -v /workspace/libfuzz/workdir/corpus/:/libfuzzpp_shared/corpus/ -it --entrypoint /bin/bash libpp-libtiff 