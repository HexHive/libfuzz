#!/bin/bash

source campaign_configuration.sh

for project in "${PROJECTS[@]}"; do
    export TARGET=$project
    ../docker/run_analysis.sh
done
