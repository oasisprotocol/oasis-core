FROM ubuntu:18.04

# Package versions.
ARG GO_VERSION=1.13.4
ARG GO_PROTOC_VERSION=3.6.1
ARG GO_PROTOC_GEN_GO_VERSION=1.2.0
ARG GOLANGCILINT_VERSION=1.18.0
ARG RUST_NIGHTLY_VERSION=2019-08-26

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
RUN wget https://github.com/google/protobuf/releases/download/v${GO_PROTOC_VERSION}/protoc-${GO_PROTOC_VERSION}-linux-x86_64.zip && \
    unzip protoc-${GO_PROTOC_VERSION}-linux-x86_64.zip -x readme.txt -d /usr && \
    rm protoc-${GO_PROTOC_VERSION}-linux-x86_64.zip && \
    chmod a+rx /usr/bin/protoc

# Install Rust.
RUN curl "https://sh.rustup.rs" -sfo rustup.sh && \
    sh rustup.sh -y --default-toolchain nightly-${RUST_NIGHTLY_VERSION} && \
    rustup target add x86_64-fortanix-unknown-sgx && \
    rustup component add rustfmt && \
    cargo install fortanix-sgx-tools sgxs-tools && \
    cargo install cargo-audit

# Install Go and utilities.
RUN wget https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz && \
    mkdir -p /go/bin && \
    # Install a specific version of protoc-gen-go.
    GO111MODULE=on go get github.com/golang/protobuf/protoc-gen-go@v${GO_PROTOC_GEN_GO_VERSION} && \
    # Install golangci-lint.
    curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | bash -s -- -b /tmp/bin v${GOLANGCILINT_VERSION} && \
    mv /tmp/bin/golangci-lint /go/bin && \
    # Install gocovmerge for e2e coverage.
    GO111MODULE=on go get github.com/wadey/gocovmerge@b5bfa59ec0adc420475f97f89b58045c721d761c

# Install node / npm / truffle.
RUN curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.33.11/install.sh | bash
ENV NVM_DIR="${HOME}/.nvm"
RUN . $NVM_DIR/nvm.sh && \
    nvm install lts/carbon --latest-npm && \
    nvm use lts/carbon && \
    nvm alias default node && \
    npm install -g truffle-oasis

# Install bubblewrap (we need version 0.3.3 which is not available for 18.04).
RUN wget http://archive.ubuntu.com/ubuntu/pool/main/b/bubblewrap/bubblewrap_0.3.3-2_amd64.deb && \
    echo '1cf9bdae5cfab75f292fad9ee0ef76a7c55243dbc0515709624b2a9573d19447 bubblewrap_0.3.3-2_amd64.deb' | sha256sum -c && \
    dpkg -i bubblewrap_0.3.3-2_amd64.deb && \
    rm bubblewrap_0.3.3-2_amd64.deb
