#!/bin/bash

# ./bin/extractor /workspaces/libfuzz/analysis/libtiff/work/lib/libtiff.a.bc -function TIFFClientOpen -output my_output_O0.json -t json -v v1
# ./bin/extractor /workspaces/libfuzz/analysis/libtiff/work/lib/libtiff.a.bc -function TIFFCleanup 

FUNCTION_NAME="TIFFReadDirectory"

./bin/extractor /workspaces/libfuzz/analysis/libtiff/work/lib/libtiff.a.bc -function ${FUNCTION_NAME} -output  ${FUNCTION_NAME}_O0.json -t json -v v1

./bin/extractor /workspaces/libfuzz/analysis/libtiff_O3/work/lib/libtiff.a.bc -function ${FUNCTION_NAME} -output  ${FUNCTION_NAME}_O3.json -t json -v v1