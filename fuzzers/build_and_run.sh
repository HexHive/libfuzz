#!/bin/bash



${TARGET}/build_driver.sh
if [[ -n "${BUILD_AND_RUN}" ]]; then
    ${LIBPP_R}/fuzzers/run.sh
fi