#!/bin/bash

rm -drf workdir_XX_X
cp `pwd`/../oss-llm-targets workdir_XX_X -r
export CONF=ossllm; ./run_rebuild_drivers.sh; ./run_fuzzing.sh; ./run_coverage.sh; ./get_total_library_coverage.sh; ./post_process.sh;
