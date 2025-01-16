#!/bin/bash

export CONF=ossllm; ./run_fuzzing.sh; ./run_coverage.sh; ./get_total_library_coverage.sh; ./post_process.sh;
