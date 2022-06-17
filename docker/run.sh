#!/bin/bash

# --env driver0 ## to verify

docker run \
    -v /workspace/libfuzz/workdir/reports/:/libfuzzpp_shared/findings/ \
    -v /workspace/libfuzz/workdir/drivers/:/libfuzzpp_shared/drivers/ \
    -v /workspace/libfuzz/workdir/corpus/:/libfuzzpp_shared/corpus/ \
    libpp-$TARGET 

# docker run -v /workspace/libfuzz/workdir/reports/:/libfuzzpp_shared/findings/ -v /workspace/libfuzz/workdir/drivers/:/libfuzzpp_shared/drivers/ -v /workspace/libfuzz/workdir/corpus/:/libfuzzpp_shared/corpus/ -it --entrypoint /bin/bash libpp-libtiff 