#!/bin/bash

OLD_DRIVER=old_driver.txt

FOLDER=libpcap/drivers

CNT=0
# while IFS= read -r odrv; do
for odrv in `ls $FOLDER`; do
    echo "$odrv -> driver$CNT.cc"
    mv "$FOLDER/$odrv" "$FOLDER/driver$CNT.cc"
    CNT=$((CNT + 1))
done
# done < ${OLD_DRIVER}