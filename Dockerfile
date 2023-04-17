# syntax=docker/dockerfile:1

FROM ubuntu:20.04 AS libfuzzpp_dev_image

WORKDIR /root

RUN apt-get -q update && \
    DEBIAN_FRONTEND="noninteractive" \ 
    apt-get -y install --no-install-suggests --no-install-recommends \
    sudo make ninja-build texinfo bison zsh ccache autoconf libtool \
    zlib1g-dev liblzma-dev libjpeg-turbo8-dev automake cmake nasm \ 
    build-essential git openssh-client python3 python3.9 python3-dev \
    python3-setuptools python-is-python3 python3-venv python3-pip \
    libtool libtool-bin libglib2.0-dev wget vim jupp nano \
    bash-completion less apt-utils apt-transport-https curl  \
    ca-certificates gnupg dialog libpixman-1-dev gnuplot-nox \
    nodejs npm graphviz libtinfo-dev libz-dev zip unzip libclang-12-dev \
    tmux tree gdb \
    && rm -rf /var/lib/apt/lists/*

# Clang dependencies
RUN apt-get update && apt-get full-upgrade -y && \
    apt-get -y install --no-install-suggests --no-install-recommends  \
    clang-12 clang-tools-12 lldb llvm gcc g++ libncurses5 clang

# LLVM from source code
COPY ./LLVM /root/LLVM
RUN cd /root/LLVM && ./fetch_repos.sh
RUN cd /root/LLVM && ./build.sh
ENV LLVM_DIR /root/llvm-build/
ENV LIBFUZZ /workspaces/libfuzz

# SVF
RUN git clone https://github.com/SVF-tools/SVF.git && \
    cd SVF && \ 
    git checkout 1c09651a6c4089402b1c072a1b0ab901bc963846 && \
    ./build.sh
RUN cd SVF && ./setup.sh

COPY ./requirements.txt /root/python/requirements.txt
RUN cd /root/python && python3.9 -m pip install -r requirements.txt
RUN pip3 install ipython

RUN sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

# TARGET FOR LIBRARY ANALYSIS
FROM libfuzzpp_dev_image AS libfuzzpp_analysis

# simple_connection is a toy example library (not even sure it works)
ARG target_name=simple_connection

ENV TARGET ${LIBFUZZ}/analysis/${target_name}
ENV TARGET_NAME ${target_name}
ENV TOOLS_DIR /root/

RUN mkdir -p ${TOOLS_DIR}/condition_extractor/
RUN mkdir -p ${TOOLS_DIR}/tool/misc/
COPY ./condition_extractor ${TOOLS_DIR}/condition_extractor/
COPY ./tool/misc/extract_included_functions.py ${TOOLS_DIR}/tool/misc/
RUN cd ${TOOLS_DIR}/condition_extractor && ./bootstrap.sh && make

WORKDIR ${LIBFUZZ}/targets/${TARGET_NAME}
CMD ${LIBFUZZ}/targets/${TARGET_NAME}/analysis.sh

# TARGET FOR DRIVER GENERATION
FROM libfuzzpp_dev_image AS libfuzzpp_drivergeneration

ARG target_name=simple_connection

ENV TARGET_NAME ${target_name}
ENV TARGET ${LIBFUZZ}/targets/${target_name}

WORKDIR ${LIBFUZZ}/targets/${TARGET_NAME}
CMD ${LIBFUZZ}/targets/${TARGET_NAME}/generate_drivers.sh

# TARGET FOR FUZZING SESSION
FROM libfuzzpp_dev_image AS libfuzzpp_fuzzing

ARG target_name=simple_connection
# ARG timeout=10m
# ARG driver=*.cc

ENV TARGET_NAME ${target_name}
ENV TARGET /library

# I want to install the library at building time, so later I only need to build
# the drivers
COPY ./targets/${TARGET_NAME} ${LIBFUZZ}/targets/${TARGET_NAME}
WORKDIR ${LIBFUZZ}/targets/${TARGET_NAME}
RUN ./build_library.sh

WORKDIR ${LIBFUZZ}
CMD ${LIBFUZZ}/targets/${TARGET_NAME}/fuzz_driver.sh