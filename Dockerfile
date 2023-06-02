# syntax=docker/dockerfile:1

FROM ubuntu:22.04 AS libfuzzpp_dev_image

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
        gcc g++ libncurses5 


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
        && chown -R root /usr/bin/sudo \
    && chmod 4755 /usr/bin/sudo \
    && chown -R $USERNAME /home/$USERNAME

ENV HOME=/home/${USERNAME}
USER ${USERNAME}
WORKDIR ${HOME}
ENV CCACHE_DIR=${HOME}/.ccache
RUN echo "export PATH=\$PATH:${HOME}/.local/bin" >> ~/.bashrc
RUN echo "export PATH=\$PATH:${HOME}/.local/bin" >> ~/.zshrc
RUN --mount=type=cache,target=${CCACHE_DIR} mkdir -p ${CCACHE_DIR} && sudo -E chown -R ${USERNAME}:${USERNAME} ${CCACHE_DIR}

RUN pip3 install ipython
RUN sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

ENV LIBFUZZ /workspaces/libfuzz

# SVF
RUN --mount=type=cache,target=${HOME}/.ccache/ git clone https://github.com/HexHive/SVF.git && \
    cd SVF && \ 
    git checkout libfuzz && \
    sed -i 's/jobs=4/jobs=/g' build.sh && \
    ./build.sh
RUN cd SVF && ./setup.sh

COPY ./requirements.txt ${HOME}/python/requirements.txt
RUN cd ${HOME}/python && python3.10 -m pip install -r requirements.txt


RUN --mount=type=cache,target=/var/cache/apt sudo apt-get update && sudo apt-get full-upgrade -y && \
    DEBIAN_FRONTEND="noninteractive" \ 
    sudo apt-get -y install --no-install-suggests --no-install-recommends \
        gcc g++ libncurses5  clang-13 llvm-13-dev

# TARGET FOR LIBRARY ANALYSIS
FROM libfuzzpp_dev_image AS libfuzzpp_analysis

ENV TOOLS_DIR ${HOME}

ENV LLVM_DIR /usr/
RUN mkdir -p ${TOOLS_DIR}/condition_extractor/
RUN mkdir -p ${TOOLS_DIR}/tool/misc/
COPY --chown=${USERNAME}:${USERNAME} ./condition_extractor ${TOOLS_DIR}/condition_extractor/
COPY --chown=${USERNAME}:${USERNAME} ./tool/misc/extract_included_functions.py ${TOOLS_DIR}/tool/misc/
RUN cd ${TOOLS_DIR}/condition_extractor && rm -Rf CMakeCache.txt && ./bootstrap.sh && make -j 

# NOTE: start_analysis.sh finds out its configuration automatically

COPY LLVM/update-alternatives-clang.sh .
RUN sudo ./update-alternatives-clang.sh 13 200
ENV PATH $PATH:${HOME}/.local/bin
CMD ${LIBFUZZ}/targets/start_analysis.sh

# TARGET FOR DRIVER GENERATION
FROM libfuzzpp_dev_image AS libfuzzpp_drivergeneration

ARG target_name=simple_connection

# NOTE: start_generate_drivers.sh finds out its configuration automatically
WORKDIR ${LIBFUZZ}/targets/${TARGET_NAME}
CMD ${LIBFUZZ}/targets/start_generate_drivers.sh

# TARGET FOR FUZZING SESSION
FROM libfuzzpp_dev_image AS libfuzzpp_fuzzing

ARG target_name=simple_connection
# ARG timeout=10m
# ARG driver=*.cc

ENV TARGET_NAME ${target_name}
ENV TARGET ${HOME}/library
ENV DRIVER_FOLDER ${LIBFUZZ}/workdir/${TARGET_NAME}/drivers

# I want to install the library at building time, so later I only need to build
# the drivers
WORKDIR ${LIBFUZZ}/targets/${TARGET_NAME}
COPY --chown=${USERNAME}:${USERNAME}  ./targets/${TARGET_NAME}/preinstall.sh ${LIBFUZZ}/targets/${TARGET_NAME}  
RUN sudo ./preinstall.sh
COPY --chown=${USERNAME}:${USERNAME}  ./targets/${TARGET_NAME}/fetch.sh ${LIBFUZZ}/targets/${TARGET_NAME}  
RUN ./fetch.sh
COPY --chown=${USERNAME}:${USERNAME}  ./targets/${TARGET_NAME}/build_library.sh ${LIBFUZZ}/targets/${TARGET_NAME}  
RUN ./build_library.sh

# NOTE: start_fuzz_driver.sh finds out its configuration automatically
WORKDIR ${LIBFUZZ}
CMD ${LIBFUZZ}/targets/start_fuzz_driver.sh
