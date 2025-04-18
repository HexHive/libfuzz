# Base Information
FROM ubuntu:20.04
LABEL org.opencontainers.image.authors="joonun.jang@samsung.com"

### Install packages/tools for build
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
RUN apt-get update \
    && apt-get install -y \
      build-essential \
      software-properties-common \
      wget \
      lsb-release \
      git \
      libz-dev \
      gdb \
      tmux \
      ninja-build \
      libboost-test-dev

# Install cmake
RUN wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null \
      | gpg --dearmor - \
      | tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null \
    && echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ bionic main' \
      | tee /etc/apt/sources.list.d/kitware.list >/dev/null \
    && apt-get update  \
    && rm /usr/share/keyrings/kitware-archive-keyring.gpg \
    && apt-get install -y kitware-archive-keyring \
    && apt-get install -y cmake


### Dependent libraries

# Install LLVM
RUN wget https://apt.llvm.org/llvm.sh  \
    && chmod +x ./llvm.sh \
    && ./llvm.sh 12 \
    && rm ./llvm.sh \
    && apt-get install -y libclang-12-dev \
    && update-alternatives  \
      --install /usr/bin/clang      clang       /usr/bin/clang-12 99 \
      --slave   /usr/bin/clang++    clang++     /usr/bin/clang++-12 \
    && update-alternatives \
      --install /usr/bin/llvm-config  llvm-config /usr/bin/llvm-config-12 99 \
      --slave   /usr/bin/llvm-link    llvm-link   /usr/bin/llvm-link-12 \
      --slave   /usr/bin/llvm-ar      llvm-ar     /usr/bin/llvm-ar-12

# Install Protobuf
RUN apt-get install -y autoconf libtool \
    && git clone https://github.com/protocolbuffers/protobuf.git \
        -b v3.14.0 \
        --depth 1 \
    && cd protobuf \
    && git submodule update --init --recursive \
    && ./autogen.sh \
    && ./configure \
    && make -j8 \
    && make install \
    && ldconfig \
    && cd - \
    && rm -rf protobuf

# Install googletest
RUN git clone https://github.com/google/googletest.git \
      -b release-1.8.1 \
      --depth 1 \
    && cd googletest \
    && cmake -B build -S . \
    && cmake --build build -j8 \
    && cmake --install build \
    && ldconfig \
    && cd - \
    && rm -rf googletest

### Fuzzer dependency

# Install libprotobuf-mutator
RUN apt-get install -y liblzma-dev \
    && git clone https://github.com/google/libprotobuf-mutator.git \
      -b v1.0  \
      --depth 1 \
    && cd libprotobuf-mutator \
    && cmake  \
      -B build \
      -GNinja \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_BUILD_TYPE=Debug \
      -S . \
    && cmake --build build \
    && cmake --install build \
    && cd - \
    && rm -rf libprotobuf-mutator

### Setup Compiler Hooker
COPY --chmod=755 docker/hooks /usr/local/bin/
