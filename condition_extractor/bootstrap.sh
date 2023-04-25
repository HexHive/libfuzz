#!/bin/bash
set -x
set -e

. ./env.sh
# cmake .
cmake -DCMAKE_BUILD_TYPE=Debug .
