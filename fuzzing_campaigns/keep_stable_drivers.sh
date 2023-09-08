#!/bin/bash -e


./post_process.sh

mkdir -p workdir_backup
mv workdir_*_*/ workdir_backup

./select_stable_drivers.py -r results.csv
