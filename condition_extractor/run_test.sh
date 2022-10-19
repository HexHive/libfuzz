#!/bin/bash

./bin/extractor /workspaces/libfuzz/analysis/libtiff/work/lib/libtiff.a.bc -function TIFFClientOpen -output my_output.json -v
# ./bin/extractor /workspaces/libfuzz/analysis/libtiff/work/lib/libtiff.a.bc -function TIFFCleanup 
