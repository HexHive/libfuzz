#!/bin/sh

echo "[INFO] This script is to be run *on the host* before any other experiment"

pip3 install -r requirements_host.txt

cd docker
./build_llvm.sh
cd -
