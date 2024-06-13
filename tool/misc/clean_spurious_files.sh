#!/bin/bash

find -maxdepth 1 -type f -regextype posix-basic -regex '^.*/[^/]*[[:cntrl:]][^/]*$' -exec rm {} \;
find . -maxdepth 1 -name "<fd*" -exec rm {} \;
rm -f *.bin

echo "[INFO] NOTE: If you have better way to remove temporary files feel free to update $0"