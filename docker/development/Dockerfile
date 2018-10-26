FROM ubuntu:18.04 as intermediate

# build linux-sgx-sdk but don't include build files in final image
RUN apt-get update -qq && apt-get upgrade -qq && apt-get install -qq \
    # for SGX SDK
    build-essential git cmake \
    wget python pkg-config software-properties-common \
    autoconf automake libtool ocaml ocamlbuild \
    # for SGX PSW
    libssl-dev libcurl4-openssl-dev

RUN mkdir /root/.ssh/
# read-only github deploy key for oasislabs/linux-sgx repo
COPY deploy_key /root/.ssh/id_rsa
RUN chmod 600 /root/.ssh/id_rsa && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts && \
    git clone --depth 1 -b ekiden git@github.com:oasislabs/linux-sgx.git && \
    cd linux-sgx && \
    ./download_prebuilt.sh && make -j sdk && make -j sdk_install_pkg && \
    ./linux/installer/bin/sgx_linux_x64_sdk_*.bin --prefix /opt && \
    cd -

FROM ubuntu:18.04

RUN apt-get update -qq && apt-get upgrade -qq && apt-get install -qq \
    build-essential git gdb cmake \
    curl wget unzip \
    pkg-config software-properties-common \
    python python-pyelftools \
    # for rust openssl
    libssl-dev libcurl4-openssl-dev \
    # for rocksdb
    libsnappy-dev librocksdb-dev \
    # for benchmarks
    python3-prometheus-client && \
    apt-get autoclean && apt-get autoremove && rm -rf /var/cache/apt/archives/*

# Required because librocksdb5.8 doesn't provide it
COPY librocksdb.pc /usr/lib/x86_64-linux-gnu/pkgconfig/librocksdb.pc
# Required because rocksdb bindings search with lib prefix
RUN cp /usr/lib/x86_64-linux-gnu/pkgconfig/snappy.pc /usr/lib/x86_64-linux-gnu/pkgconfig/libsnappy.pc

ENV HOME="/root"
ENV GOPATH="/go"
ENV PATH="${HOME}/.cargo/bin:/go/bin:/usr/local/go/bin:${PATH}"

# install protobuf (apt system v3.0 fails to compile our protos)
RUN wget 'https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip' && \
    unzip protoc-3.5.1-linux-x86_64.zip -x readme.txt -d /usr && \
    rm protoc-3.5.1-linux-x86_64.zip && \
    chmod a+rx /usr/bin/protoc

# install Linux SGX SDK
# Note: myelin-ml is a lightly modified version of the intel sgx sdk at 2.1.3 with the baidu patch applied.
# https://github.com/baidu/rust-sgx-sdk/tree/master/dockerfile/experimental
COPY --from=intermediate /opt/sgxsdk /opt/sgxsdk
RUN echo "source /opt/sgxsdk/environment" >> /root/.bashrc

# install rust version supported by rust-sgx-sdk
RUN curl "https://sh.rustup.rs" -sfo rustup.sh && \
    sh rustup.sh -y --default-toolchain nightly-2018-08-25 && \
    rustup component add rust-src && \
    # rustfmt-nightly is crazily unstable, with no versions appearing to exist that
    # work with the 3-16 nightly.
    rustup update nightly-2018-05-25 && \
    cargo +nightly-2018-05-25 install rustfmt-nightly --version 0.6.1 --force && \
    cargo install xargo

# install node / npm / truffle.
RUN curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.33.11/install.sh | bash
ENV NVM_DIR="${HOME}/.nvm"
RUN . $NVM_DIR/nvm.sh && \
    nvm install lts/carbon --latest-npm && \
    nvm use lts/carbon && \
    nvm alias default node && \
    npm install -g truffle@4.1

# Install golang 1.11 and utilities.
RUN wget https://dl.google.com/go/go1.11.1.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.11.1.linux-amd64.tar.gz && \
    rm go1.11.1.linux-amd64.tar.gz && \
    mkdir -p /go/bin && \
    curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh && \
    go get -u github.com/golang/protobuf/protoc-gen-go && \
    go get -u github.com/alecthomas/gometalinter && \
    gometalinter --install
