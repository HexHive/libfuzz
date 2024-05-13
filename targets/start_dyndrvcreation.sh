#!/bin/bash

# export TARGET_NAME=${TARGET}
# export TARGET=${LIBFUZZ}/analysis/${TARGET}
# ENV TARGET_NAME ${target_name}

convert_to_seconds() {
    local time_string="$1"
    local seconds=0
    
    # Loop through each character in the time string
    while [[ -n "$time_string" ]]; do
        local num=${time_string%[a-zA-Z]*}  # Extract the number from the string
        local unit=${time_string##*[0-9]}    # Extract the unit from the string
        
        case "$unit" in
            "s") seconds=$((seconds + num));;
            "m") seconds=$((seconds + num * 60));;
            "h") seconds=$((seconds + num * 3600));;
        esac
        
        time_string=${time_string#*[a-zA-Z]}  # Remove the processed part from the string
    done
    
    echo "$seconds"
}

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

# timeout  -k 10s ${WHOLE_TIMEOUT} -c \

loop_duration=$(convert_to_seconds ${WHOLE_TIMEOUT})
echo "[INFO] whole fuzzing campaing is ${loop_duration}s"
echo "[INFO] single driver is ${TIMEOUT}"

start_time=$(date +%s)

while true
do
    current_time=$(date +%s)
    time_passed=$((current_time - start_time))
    if [ $time_passed -ge $loop_duration ]; then
        echo "Loop duration reached. Exiting loop."
        break
    fi

    export DRIVER=$(curl http://127.0.0.1:5000/get_new_driver 2> /dev/null)
    echo "[INFO] Get driver $DRIVER"
    # 60s w/o new seeds? let's change...
    export COV_PLATEAU_TIMEOUT=60
    ${LIBFUZZ}/targets/start_fuzz_driver.sh
    echo "[INFO] Send feedback to the driver generator"
    CAUSE_DRIVER_STOP=$(sed '1q;d' feedback.txt)
    DRIVER_EXEC_TIME=$(sed '2q;d' feedback.txt)
    curl http://127.0.0.1:5000/push_feedback?driver=${DRIVER}\&time=${DRIVER_EXEC_TIME}\&cause=${CAUSE_DRIVER_STOP} &> /dev/null

done

# bloddy way to kill the service w no mercy
kill -9 $(lsof -i :5000 | awk 'NR > 1 {print $2}')