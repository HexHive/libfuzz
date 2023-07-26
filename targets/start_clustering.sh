#!/bin/bash


echo "[INFO] COVERAGE METRICS: ${TARGET_NAME}"

source "$HOME/.cargo/env"

TARGET_WORKDIR=${LIBFUZZ}/workdir/${TARGET_NAME}
DRIVER_FOLDER=${TARGET_WORKDIR}/drivers
CRASHES=${TARGET_WORKDIR}/crashes
OUTPUT=${TARGET_WORKDIR}/clusters
LOGS=${OUTPUT}/logs

rm -Rf $OUTPUT $LOGS || true
mkdir -p $OUTPUT $LOGS

FUZZ_TARGETS="$(find ${DRIVER_FOLDER} -type f -executable)"


echo $DRIVER_FOLDER

for d in $FUZZ_TARGETS
do
    DRIVER_NAME=$(basename $d)
    echo "CLUSTERING: ${DRIVER_NAME}"
    casr-libfuzzer -i ${CRASHES}/${DRIVER_NAME} -o ${OUTPUT}/${DRIVER_NAME} -- $d &> ${LOGS}/${DRIVER_NAME}
done
