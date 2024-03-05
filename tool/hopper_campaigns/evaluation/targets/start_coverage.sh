#!/bin/bash

set -e
set -x


cd ${TARGET}

SEED_DIR=./output/queue hopper cov output_cov

