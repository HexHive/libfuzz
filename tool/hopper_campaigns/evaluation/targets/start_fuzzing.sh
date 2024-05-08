#!/bin/bash

set -e
set -x

cd ${TARGET}

timeout ${TIMEOUT} hopper fuzz

