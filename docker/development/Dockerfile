FROM ubuntu:20.04

# Package versions.
ARG GO_VERSION=1.16.3
ARG GO_NANCY_VERSION=1.0.0
ARG GO_NANCY_CHECKSUM=13804837a34c07e7a933b0d6f52c5e580b03ccb209e38fc3d6394b791b414c33
ARG GO_PROTOC_VERSION=3.6.1
ARG GO_PROTOC_GEN_GO_VERSION=1.21.0
ARG GOLANGCILINT_VERSION=1.28.2
ARG GOCOVMERGE_VERSION=b5bfa59ec0adc420475f97f89b58045c721d761c
ARG GOFUMPT_VERSION=abc0db2c416aca0f60ea33c23c76665f6e7ba0b6
ARG RUST_NIGHTLY_VERSION=2021-05-20
ARG JEMALLOC_VERSION=5.2.1
ARG JEMALLOC_CHECKSUM=34330e5ce276099e2e8950d9335db5a875689a4c6a56751ef3b1d8c537f887f6

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get upgrade -qq && apt-get install -qq \
    build-essential git gdb cmake \
    curl wget unzip \
    pkg-config software-properties-common \
    python3 python3-pyelftools \
    # for gitlint
    python3-pip \
    # for rust openssl
    libssl-dev libcurl4-openssl-dev \
    # for benchmarks
    python3-prometheus-client \
    # for seccomp Go bindings support
    libseccomp-dev \
    bubblewrap && \
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
    cargo install --version 0.4.0 fortanix-sgx-tools && \
    cargo install --version 0.8.2 sgxs-tools && \
    cargo install cargo-audit

# Install Go and utilities.
RUN wget https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz && \
    mkdir -p /go/bin && \
    # Install a specific version of protoc-gen-go.
    GO111MODULE=on go get google.golang.org/protobuf/cmd/protoc-gen-go@v${GO_PROTOC_GEN_GO_VERSION} && \
    # Install golangci-lint.
    curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | bash -s -- -b /tmp/bin v${GOLANGCILINT_VERSION} && \
    mv /tmp/bin/golangci-lint /go/bin && \
    # Install gocovmerge for e2e coverage.
    GO111MODULE=on go get github.com/wadey/gocovmerge@${GOCOVMERGE_VERSION} && \
    # Install nancy for auditing dependencies.
    curl -sfL -o nancy https://github.com/sonatype-nexus-community/nancy/releases/download/v${GO_NANCY_VERSION}/nancy-linux.amd64-v${GO_NANCY_VERSION} && \
    echo "${GO_NANCY_CHECKSUM} nancy" | sha256sum -c && \
    mv nancy /go/bin/nancy && \
    chmod +x /go/bin/nancy && \
    # Install gofumpt for code formatting.
    GO111MODULE=on go get mvdan.cc/gofumpt@${GOFUMPT_VERSION} && \
    GO111MODULE=on go get mvdan.cc/gofumpt/gofumports@${GOFUMPT_VERSION}

# Install jemalloc (used by BadgerDB).
RUN wget -O jemalloc.tar.bz2 \
    https://github.com/jemalloc/jemalloc/releases/download/${JEMALLOC_VERSION}/jemalloc-${JEMALLOC_VERSION}.tar.bz2 && \
    # Ensure checksum matches.
    echo "${JEMALLOC_CHECKSUM}  jemalloc.tar.bz2" | sha256sum -c && \
    tar -xf jemalloc.tar.bz2 && \
    cd jemalloc-${JEMALLOC_VERSION} && \
    # Ensure reproducible jemalloc build.
    # https://reproducible-builds.org/docs/build-path/
    EXTRA_CXXFLAGS=-ffile-prefix-map=$(pwd -L)=. EXTRA_CFLAGS=-ffile-prefix-map=$(pwd -L)=. \
    ./configure --with-jemalloc-prefix='je_' --with-malloc-conf='background_thread:true,metadata_thp:auto' && \
    make && \
    make install && \
    cd .. && rm jemalloc.tar.bz2 && rm -rf jemalloc-${JEMALLOC_VERSION}
