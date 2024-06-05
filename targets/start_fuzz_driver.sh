#!/bin/bash

${LIBFUZZ}/targets/${TARGET_NAME}/compile_driver.sh

if [ "$TIMEOUT" -eq "0" ]; then
	echo "No Timeout, just compile"
	exit 0
fi

echo "[INFO] DRIVER_FOLDER: ${DRIVER_FOLDER}"

for d in `find ${DRIVER_FOLDER} -type f -executable -name "${DRIVER}"`
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

    FORK_MODE=""
    if [ -z "${COV_PLATEAU_TIMEOUT}" ]; then
        FORK_MODE="-fork=1"
    fi

    # echo "COV_PLATEAU_TIMEOUT: ${COV_PLATEAU_TIMEOUT}"
    echo "FORK_MODE: ${FORK_MODE}"

    # FORK_MODE CONTROLS FORK-MODE (captain obvious here!).  
    # IF COV_PLATEAU_TIMEOUT, I DO NOT WANT TO FORK.   
    # IF FORK MODE IS ON, KEEP GOING TILL SOMEONE KILLS THE FUZZER
    (sleep $TIMEOUT && pkill ${DRIVER_NAME}) &
    $d ${DRIVER_CORNEW} -artifact_prefix=${CRASHES_DIR}/ -ignore_crashes=1 \
        -ignore_timeouts=1 -ignore_ooms=1 -detect_leaks=0 ${FORK_MODE} -max_len=16384 || echo "Done: $d"
done
