ARG PREBUILT_LLVM_IMAGE=nbars/fuzztruction-llvm_debug:11.0.1
FROM ${PREBUILT_LLVM_IMAGE} as llvm

FROM ubuntu:20.04 as dev
ENV DEBIAN_FRONTEND noninteractive
ENV CCACHE_DIR=/ccache
ENV CCACHE_MAXSIZE=25G

RUN sed -i "s/^# deb-src/deb-src/g" /etc/apt/sources.list

RUN apt update -y && yes | unminimize && apt-mark hold "llvm-*" && apt-mark hold "clang-*"
RUN \
    apt update -y && apt install -y build-essential git cmake binutils-gold gosu sudo valgrind python3-pip wget \
    bison flex \
    zsh powerline fonts-powerline iputils-ping iproute2 ripgrep \
    libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev \
    ccache locales rr htop strace ltrace tree nasm \
    lsb-release ubuntu-dbgsym-keyring texinfo \
    neovim bear ccache locales rr htop strace \
    ltrace tree nasm lsb-release ubuntu-dbgsym-keyring gcc-multilib \
    linux-tools-generic \
    curl ninja-build xdot aspell-en neovim libgmp-dev tmux \
    man psmisc lsof rsync zip unzip qpdf ncdu fdupes parallel \
    texlive texlive-latex-extra texlive-fonts-recommended dvipng cm-super \
    virtualenv python2 g++ libz3-dev zlib1g-dev libc++-dev mercurial nano

RUN sudo pip3 install mypy pylint matplotlib pyelftools lit pyyaml psutil


# Copy prebuilt custom LLVM version
# By default nbars/fuzztruction-llvm_debug:11.0.1
# DIGEST:sha256:56e1b3c584f82ce645ce5f7a32765a82ca82a6c5c23bed988d30d2d6cd187281
COPY --from=llvm /llvm/* /usr

RUN locale-gen en_US.UTF-8
ARG USER_UID=1000
ARG USER_GID=1000

#Enable sudo group
RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
WORKDIR /tmp

RUN update-locale LANG=en_US.UTF-8
ENV LANG=en_US.UTF-8

# Install AFL++
RUN git clone https://github.com/AFLplusplus/AFLplusplus -b 4.00c && cd AFLplusplus && make all && make install

# Make sure the loader finds our agent library.
COPY data/ld_fuzztruction.conf /etc/ld.so.conf.d/fuzztruction.conf

#Create user "user"
RUN groupadd -g ${USER_GID} user
# -l -> https://github.com/moby/moby/issues/5419
RUN useradd -l --shell /bin/bash -c "" -m -u ${USER_UID} -g user -G sudo user
WORKDIR "/home/user"

RUN echo "set speller \"aspell -x -c\"" > /etc/nanorc

RUN cd /tmp && \
    apt install autoconf -y && \
    git clone https://github.com/NixOS/patchelf.git && \
    cd patchelf && \
    ./bootstrap.sh && \
    ./configure && \
    make && \
    make check && \
    make install

USER user
RUN wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py \
  && echo source ~/.gdbinit-gef.py >> ~/.gdbinit

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y --default-toolchain nightly-2022-09-06
ENV PATH="/home/user/.cargo/bin:${PATH}"

RUN sh -c "$(wget -O- https://raw.githubusercontent.com/deluan/zsh-in-docker/master/zsh-in-docker.sh)" -- \
    -t agnoster

# Install DynamoRIO
RUN  wget https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-9.0.19078/DynamoRIO-Linux-9.0.19078.tar.gz && \
     tar -xzvf DynamoRIO-Linux-9.0.19078.tar.gz && \
     rm DynamoRIO-Linux-9.0.19078.tar.gz

COPY symcc/*.patch /tmp/

# Build symcc with qsym backend
RUN cd / && \
    git config --global --add safe.directory /symcc && \
    sudo git clone https://github.com/eurecom-s3/symcc.git && cd symcc && \
    sudo git checkout 07c8895fea8e5fae90417df60a130be7a9c63d92 && \
    sudo chown -R user:user /symcc && \
    git submodule init && git submodule update && \
    cp /tmp/symcc.patch . && \
    git apply symcc.patch && \
    cmake -G Ninja -DQSYM_BACKEND=ON -DZ3_TRUST_SYSTEM_VERSION=on . && \
    ninja check && \
    cd util/symcc_fuzzing_helper && \
    cargo build --release

# Build symcc with simple backend
RUN cd / && \
    git config --global --add safe.directory /symcc-simple-backend && \
    sudo git clone https://github.com/eurecom-s3/symcc.git symcc-simple-backend  && cd symcc-simple-backend && \
    sudo git checkout 07c8895fea8e5fae90417df60a130be7a9c63d92 && \
    sudo chown -R user:user /symcc-simple-backend && \
    git submodule init && git submodule update && \
    cp /tmp/symcc.patch . && \
    git apply symcc.patch && \
    cmake -G Ninja -DQSYM_BACKEND=OFF -DZ3_TRUST_SYSTEM_VERSION=on . && \
    ninja check

# Build the c++ std library with symcc support.
RUN cd / && \
    sudo mkdir -p /libcxx_symcc && \
    sudo git clone https://github.com/llvm/llvm-project.git --branch llvmorg-11.1.0 libcxx_symcc_build && \
    cd /libcxx_symcc_build && \
    sudo chown -R user:user /libcxx_symcc_build && \
    export SYMCC_REGULAR_LIBCXX=yes; \
    export SYMCC_NO_SYMBOLIC_INPUT=yes; \
    mkdir build; cd build; cmake -G Ninja ../llvm \
        -DLLVM_ENABLE_PROJECTS="libcxx;libcxxabi" \
        -DLLVM_TARGETS_TO_BUILD="X86" \
        -DLLVM_DISTRIBUTION_COMPONENTS="cxx;cxxabi;cxx-headers" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/libcxx_symcc \
        -DCMAKE_C_COMPILER=/symcc-simple-backend/symcc \
        -DCMAKE_CXX_COMPILER=/symcc-simple-backend/sym++  && \
    sudo -E ninja distribution && \
    sudo -E ninja install-distribution

# Install WEIZZ
USER root
RUN sudo apt install libtool-bin python -y && \
    cd / && \
    mkdir -p weizz-fuzzer && \
    git clone --depth 1 https://github.com/andreafioraldi/weizz-fuzzer.git weizz-fuzzer && \
    cd weizz-fuzzer && \
    git checkout c9cbeef0b057b9f7dc62af9b20629090b1b9fe4f && \
    make

COPY env/check_env.sh /usr/bin/
USER user
