#!/bin/bash

# export TARGET_NAME=${TARGET}
# export TARGET=${LIBFUZZ}/analysis/${TARGET}
# ENV TARGET_NAME ${target_name}

# echo "[TOOLS_DIR] ${TOOLS_DIR}"
echo "[TARGET] ${TARGET}"

${LIBFUZZ}/tool/service.py \
    --config ${LIBFUZZ}/targets/${TARGET_NAME}/generator.toml \
    --overwrite ${LIBFUZZ}/overwrite.toml &> service.log &

SRV_TO_START=3s
echo "[INFO] Wait ${SRV_TO_START} till service bootsrap"
sleep ${SRV_TO_START}

# http://127.0.0.1:5000 -- localhost
SERVICE_ENDPOINT="http://127.0.0.1:5000"

# # NOTE: these env vars must be set in Dockerfile
# export DRIVER_FOLDER=${LIBFUZZ}/workdir/${TARGET_NAME}/drivers
# export CORPUS_FOLDER=${LIBFUZZ}/workdir/${TARGET_NAME}/corpus_new
# export LLVM_DIR=/usr

for i in $(seq 1 3); do
    export DRIVER=$(curl http://127.0.0.1:5000/get_new_driver 2> /dev/null)
    echo "[INFO] Get driver $DRIVER"
    export TIMEOUT=20
    ${LIBFUZZ}/targets/start_fuzz_driver.sh
    echo "[INFO] Send feedback to the driver generator"
    # TODO: find a way to get execution time from the fuzzer
    curl http://127.0.0.1:5000/push_feedback?driver=${DRIVER}\&time=10 &> /dev/null
done

# bloddy way to kill the service w no mercy
kill -9 $(lsof -i :5000 | awk 'NR > 1 {print $2}')