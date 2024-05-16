#!/bin/bash

source campaign_configuration.sh

HOST_PORT_NEW=5000
for project in "${PROJECTS[@]}"; do
    export TARGET=$project
    export HOST_PORT=${HOST_PORT_NEW}
    ../docker/run_dyn_drivergeneration.sh
    # new port
    HOST_PORT_NEW=$((HOST_PORT_NEW+1))
done