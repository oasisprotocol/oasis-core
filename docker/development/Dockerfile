FROM ubuntu:18.04

ARG GO_VERSION=1.12
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get upgrade -qq && apt-get install -qq \
    build-essential git gdb cmake \
    curl wget unzip \
    pkg-config software-properties-common \
    python python-pyelftools \
    # for gitlint
    python-pip \
    # for rust openssl
    libssl-dev libcurl4-openssl-dev \
    # for benchmarks
    python3-prometheus-client \
    # for seccomp Go bindings support
    libseccomp-dev \
    # for bubblewrap
    libcap2 && \
    apt-get autoclean && apt-get autoremove && rm -rf /var/cache/apt/archives/* && \
    # for linting Git commits
    pip install gitlint

ENV HOME="/root"
ENV GOPATH="/go"
ENV PATH="${HOME}/.cargo/bin:/go/bin:/usr/local/go/bin:${PATH}"

# Install protobuf (apt system v3.0 fails to compile our protos).
RUN wget 'https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip' && \
    unzip protoc-3.5.1-linux-x86_64.zip -x readme.txt -d /usr && \
    rm protoc-3.5.1-linux-x86_64.zip && \
    chmod a+rx /usr/bin/protoc

# Install Rust.
RUN curl "https://sh.rustup.rs" -sfo rustup.sh && \
    sh rustup.sh -y --default-toolchain nightly-2019-03-21 && \
    rustup target add x86_64-fortanix-unknown-sgx && \
    rustup component add rustfmt && \
    cargo install fortanix-sgx-tools sgxs-tools && \
    cargo install xargo

# Install Go and utilities.
RUN wget https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz && \
    mkdir -p /go/bin && \
    # Install a specific version of protoc-gen-go (1.2.0).
    go get -d github.com/golang/protobuf/protoc-gen-go && \
    cd /go/src/github.com/golang/protobuf && \
    git checkout v1.2.0 && \
    cd protoc-gen-go && \
    go install && \
    # Install golangci-lint.
    curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | bash -s -- -b /tmp/bin v1.15.0 && \
    mv /tmp/bin/golangci-lint /go/bin

# Install node / npm / truffle.
RUN curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.33.11/install.sh | bash
ENV NVM_DIR="${HOME}/.nvm"
RUN . $NVM_DIR/nvm.sh && \
    nvm install lts/carbon --latest-npm && \
    nvm use lts/carbon && \
    nvm alias default node && \
    npm install -g truffle-oasis

# Install bubblewrap (we need version 0.3.1 which is not available for 18.04).
RUN wget http://archive.ubuntu.com/ubuntu/pool/main/b/bubblewrap/bubblewrap_0.3.1-2_amd64.deb && \
    echo '348ff7e71cac05d9e8f154ecc24ad1c9461e76b4ff23e992dcb60f9da51247af bubblewrap_0.3.1-2_amd64.deb' | sha256sum -c && \
    dpkg -i bubblewrap_0.3.1-2_amd64.deb && \
    rm bubblewrap_0.3.1-2_amd64.deb
