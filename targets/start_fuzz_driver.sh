#!/bin/bash

${LIBFUZZ}/targets/${TARGET_NAME}/compile_driver.sh

echo "[INFO] DRIVER_FOLDER: ${DRIVER_FOLDER}"

for d in ` find ${DRIVER_FOLDER} -type f -executable -name "${DRIVER}"`
do
    echo $d
    DRIVER_NAME=$(basename $d)
    echo "Fuzzing ${TIMEOUT}: ${DRIVER_NAME}"
    DRIVER_CORPUS=${LIBFUZZ}/workdir/${TARGET_NAME}/corpus/${DRIVER_NAME}
    DRIVER_CORNEW=${LIBFUZZ}/workdir/${TARGET_NAME}/corpus_new/${DRIVER_NAME}
    CRASHES_DIR=${LIBFUZZ}/workdir/${TARGET_NAME}/crashes/${DRIVER_NAME}
    rm -Rf ${CRASHES_DIR} || true
    rm -Rf ${DRIVER_CORNEW} || true
    mkdir -p ${CRASHES_DIR}
    mkdir -p ${DRIVER_CORNEW}

    # make a copy of initial corpus
    cp -r ${DRIVER_CORPUS}/* ${DRIVER_CORNEW}/
    
    # # THIS IS WITH STANDARD MODE -- STOP AT THE FIRST CRASHE
    # timeout $TIMEOUT $d ${DRIVER_CORPUS} \
    #     -artifact_prefix=${CRASHES_DIR}/ || echo "Done: $d"

    # THIS IS WITH FORK-MODE -- KEEP GOING TILL SOMEONE KILLS IT
    (sleep $TIMEOUT && pkill ${DRIVER_NAME}) &
    $d ${DRIVER_CORNEW} -artifact_prefix=${CRASHES_DIR}/ -ignore_crashes=1 \
        -ignore_timeouts=1 -ignore_ooms=1 -fork=1 || echo "Done: $d"
done