#!/bin/bash

docker run \
    -v /workspace/libfuzz/workdir/reports/:/libfuzzpp_shared/findings/ \
    -v /workspace/libfuzz/workdir/drivers/:/libfuzzpp_shared/drivers/ \
    libpp-$TARGET 