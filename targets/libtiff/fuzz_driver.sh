#!/bin/bash
set -e

##
# Pre-requirements:
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, FLAGS, LIBS, etc...
##

# if [ ! -d "$TARGET/repo" ]; then
#     echo "fetch.sh must be executed first."
#     exit 1
# fi

WORK="$TARGET/work"

cd "$TARGET/repo"

CXX=$LLVM_DIR/bin/clang++
CC=$LLVM_DIR/bin/clang

DRIVER_FOLDER=${LIBFUZZ}/workdir/${TARGET_NAME}/drivers
echo "Compiling: ${DRIVER_FOLDER}/${DRIVER}.cc"

for d in `ls ${DRIVER_FOLDER}/${DRIVER}.cc`
do
    echo "Driver: $d"
    $CXX -g -std=c++11  -fsanitize=fuzzer,address -I/${TARGET}/work/include \
        $d ${TARGET}/work/lib/libtiff.a ${TARGET}/work/lib/libtiffxx.a \
        -lz -ljpeg -Wl,-Bstatic -llzma -Wl,-Bdynamic -lstdc++ -o "${d%%.*}"
done

for d in ` find ${DRIVER_FOLDER} -type f -executable -name "{$DRIVER}"`
do
    DRIVER_NAME=$(basename $d)
    echo "Fuzzing ${TIMEOUT}: ${DRIVER_NAME}"
    DRIVER_CORPUS=${LIBFUZZ}/workdir/${TARGET_NAME}/corpus/${DRIVER_NAME}
    CRASHES_DIR=${LIBFUZZ}/workdir/${TARGET_NAME}/crashes/${DRIVER_NAME}
    mkdir -p ${CRASHES_DIR}
    
    # THIS IS WITH STANDARD MODE -- STOP AT THE FIRST CRASHE
    # timeout $TIMEOUT $d ${DRIVER_CORPUS} \
    #     -artifact_prefix=${CRASHES_DIR}/ || echo "Done: $d"

    # THIS IS WITH FORK-MODE -- KEEP GOING TILL SOMEONE KILLS IT
    (sleep $TIMEOUT && pkill ${DRIVER_NAME}) &
    $d ${DRIVER_CORPUS} -artifact_prefix=${CRASHES_DIR}/ -ignore_crashes=1 \
        -ignore_timeouts=1 -ignore_ooms=1 -fork=1 || echo "Done: $d"
done