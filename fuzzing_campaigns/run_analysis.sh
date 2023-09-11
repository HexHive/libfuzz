#!/bin/bash

source campaign_configuration.sh

for project in "${PROJECTS[@]}"; do
    export TARGET=$project
    ../docker/run_analysis.sh
done

echo "[INFO] waiting for dockers to end"

for project in "${PROJECTS[@]}"; do
    docker wait libpp-analysis-$project
done

echo "[INFO] all analyses done!"