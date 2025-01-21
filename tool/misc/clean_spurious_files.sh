#!/bin/bash

find -maxdepth 1 -type f -regextype posix-basic -regex '^.*/[^/]*[[:cntrl:]][^/]*$' -exec rm {} \;
find . -maxdepth 1 -name "<fd*" -exec rm {} \;
rm -f *.bin
rm -f core.*

# Find all files and check each for non-printable characters
find . -maxdepth 1 -type f -print0 | while IFS= read -r -d '' file; do
        filename=$(basename "$file")
        if contains_non_printable "$filename"; then
                # echo "File with non-printable character(s): $file"
                rm "$file"
        fi
done

echo "[INFO] NOTE: If you have better way to remove temporary files feel free to update $0"