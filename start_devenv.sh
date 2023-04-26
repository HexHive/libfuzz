#!/bin/bash


# docker build -t libfpp-devenv -f Dockerfile . 
docker build -t vsc-libfuzz-230af0437939dbfc00081fc163ef918b -f Dockerfile . 
# docker run -it -v $(pwd):/home/libfuzz/libfuzz libfpp-devenv
docker run -it -v "$(pwd):/workspaces/libfuzz" vsc-libfuzz-230af0437939dbfc00081fc163ef918b zsh
