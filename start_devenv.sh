#!/bin/bash


docker build -t libfpp-devenv -f Dockerfile . 
docker run -it -v $(pwd):/root/libfuzz libfpp-devenv