#!/bin/bash

compiled_drivers=1
empty_folders_check=0
if [[ "${compiled_drivers}" -ne 0 || "${empty_folders_check}" -ne 0 ]]; then
    echo "[ERROR] in driver compilations"
    exit 1
else
    echo "[OK] all drivers correctly generated and compiled!"
fi