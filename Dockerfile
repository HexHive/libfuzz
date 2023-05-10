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

COPY ./requirements.txt /root/python/requirements.txt
RUN cd /root/python && python3.9 -m pip install -r requirements.txt
RUN cd /usr/bin && rm python && ln -s python3.9 python
RUN pip3 install ipython

RUN sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"