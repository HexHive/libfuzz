#!/bin/bash


# install LibFuzz source codes
./scripts/install-hextype-files.sh

# I may need a debug makefile in the future, not now!
# if [[ $# -eq 0 ]]; then
#   MAKEFILE=Makefile
# else
#   printf "Debug\n\n\n";
#   MAKEFILE=Makefilex_debug
# fi;

set -e
make -j
