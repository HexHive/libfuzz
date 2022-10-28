#!/bin/bash

# ./bin/extractor /workspaces/libfuzz/analysis/libtiff/work/lib/libtiff.a.bc -function TIFFClientOpen -output my_output_O0.json -t json -v v1
# ./bin/extractor /workspaces/libfuzz/analysis/libtiff/work/lib/libtiff.a.bc -function TIFFCleanup 

# FUNCTION_NAME="TIFFReadDirectory"

for FUNCTION_NAME in TIFFGetField TIFFTileSize64 TIFFClose _TIFFmalloc TIFFReadRGBAImage _TIFFfree 
do
    ./bin/extractor /workspaces/libfuzz/analysis/libtiff/work/lib/libtiff.a.bc -function ${FUNCTION_NAME} -output  ${FUNCTION_NAME}.json -t json -v v1
done