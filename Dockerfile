# syntax=docker/dockerfile:1

FROM ubuntu:20.04 AS libfuzzpp_dev_image

RUN --mount=type=cache,target=/var/cache/apt apt-get -q update && \
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
    tmux tree gdb jq bc cloc ccache \
    && rm -rf /var/lib/apt/lists/*

# Clang dependencies
RUN --mount=type=cache,target=/var/cache/apt apt-get update && apt-get full-upgrade -y && \
    DEBIAN_FRONTEND="noninteractive" \ 
    apt-get -y install --no-install-suggests --no-install-recommends \
    clang-12 clang-tools-12 lldb llvm gcc g++ libncurses5 clang

ARG USERNAME=libfuzz
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m -s/bin/zsh $USERNAME \
    # [Optional] Add sudo support. Omit if you don't need to install software after connecting.
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME \
    && chown -R root /usr/lib/sudo/sudoers.so /usr/bin/sudo /usr/lib/sudo \
    && chmod 4755 /usr/bin/sudo \
    && chown -R $USERNAME /home/$USERNAME

ENV HOME=/home/${USERNAME}
USER ${USERNAME}
WORKDIR ${HOME}
ENV CCACHE_DIR=${HOME}/.ccache
RUN --mount=type=cache,target=${CCACHE_DIR} mkdir -p ${CCACHE_DIR} && sudo -E chown -R ${USERNAME}:${USERNAME} ${CCACHE_DIR}
RUN echo "export PATH=\$PATH:${HOME}/.local/bin" >> ~/.bashrc

RUN pip3 install ipython
RUN sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

# LLVM from source code
COPY ./LLVM ${HOME}/LLVM
RUN --mount=type=cache,target=${CCACHE_DIR} cd ${HOME}/LLVM && ./fetch_repos.sh
RUN --mount=type=cache,target=${CCACHE_DIR} cd ${HOME}/LLVM && ./build.sh
ENV LIBFUZZ /workspaces/libfuzz

# SVF
ENV LLVM_DIR ${HOME}/llvm-build/
RUN --mount=type=cache,target=${HOME}/.ccache/ git clone https://github.com/SVF-tools/SVF.git && \
    cd SVF && \ 
    git checkout 1c09651a6c4089402b1c072a1b0ab901bc963846 && \
    sed -i 's/jobs=4/jobs=/g' build.sh && \
    ./build.sh
RUN cd SVF && ./setup.sh

COPY ./requirements.txt ${HOME}/python/requirements.txt
RUN cd ${HOME}/python && python3.9 -m pip install -r requirements.txt

# TARGET FOR LIBRARY ANALYSIS
FROM libfuzzpp_dev_image AS libfuzzpp_analysis

ENV TOOLS_DIR ${HOME}

RUN mkdir -p ${TOOLS_DIR}/condition_extractor/
RUN mkdir -p ${TOOLS_DIR}/tool/misc/
COPY --chown=${USERNAME}:${USERNAME} ./condition_extractor ${TOOLS_DIR}/condition_extractor/
COPY --chown=${USERNAME}:${USERNAME} ./tool/misc/extract_included_functions.py ${TOOLS_DIR}/tool/misc/
RUN cd ${TOOLS_DIR}/condition_extractor && ./bootstrap.sh && make

ENV PATH $PATH:${HOME}/.local/bin
CMD ${LIBFUZZ}/targets/start_analysis.sh

# TARGET FOR DRIVER GENERATION
FROM libfuzzpp_dev_image AS libfuzzpp_drivergeneration

ARG target_name=simple_connection

ENV TARGET_NAME ${target_name}
ENV TARGET ${LIBFUZZ}/targets/${target_name}

# NOTE: generate_drivers.sh finds out its configuration automatically
WORKDIR ${LIBFUZZ}/targets/${TARGET_NAME}
CMD ${LIBFUZZ}/targets/generate_drivers.sh

# TARGET FOR FUZZING SESSION
FROM libfuzzpp_dev_image AS libfuzzpp_fuzzing

ARG target_name=simple_connection
# ARG timeout=10m
# ARG driver=*.cc

ENV TARGET_NAME ${target_name}
ENV TARGET ${HOME}/library

# I want to install the library at building time, so later I only need to build
# the drivers
COPY --chown=${USERNAME}:${USERNAME}  ./targets/${TARGET_NAME} ${LIBFUZZ}/targets/${TARGET_NAME}  
WORKDIR ${LIBFUZZ}/targets/${TARGET_NAME}
RUN sudo ./preinstall.sh
RUN ./fetch.sh
RUN ./build_library.sh

WORKDIR ${LIBFUZZ}
CMD ${LIBFUZZ}/targets/${TARGET_NAME}/fuzz_driver.sh
