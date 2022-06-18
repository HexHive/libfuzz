#!/bin/bash

# --env BUILD_AND_RUN=1 \

for i in {0..19}
do
    docker run \
        -v /workspace/libfuzz/workdir/reports/:/libfuzzpp_shared/findings/ \
        -v /workspace/libfuzz/workdir/drivers/:/libfuzzpp_shared/drivers/ \
        -v /workspace/libfuzz/workdir/corpus/:/libfuzzpp_shared/corpus/ \
        --env PROGRAM=driver$i \
        libpp-$TARGET 
done

# docker run -v /workspace/libfuzz/workdir/reports/:/libfuzzpp_shared/findings/ -v /workspace/libfuzz/workdir/drivers/:/libfuzzpp_shared/drivers/ -v /workspace/libfuzz/workdir/corpus/:/libfuzzpp_shared/corpus/ -it --entrypoint /bin/bash libpp-libtiff 