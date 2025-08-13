FROM ubuntu:22.04

# Package versions.
ARG GO_VERSION=1.25.0
ARG GO_NANCY_VERSION=1.0.33
ARG GO_NANCY_CHECKSUM=a4bf5290d41b095c04f941ed5380674770c79d59735e33b1bd07a5cd5fbb135d
ARG GO_PROTOC_VERSION=3.6.1
ARG GO_PROTOC_GEN_GO_VERSION=1.21.0
ARG GOLANGCILINT_VERSION=2.3.1
ARG GOCOVMERGE_VERSION=b5bfa59ec0adc420475f97f89b58045c721d761c
ARG GOFUMPT_VERSION=v0.8.0
ARG GOIMPORTS_VERSION=v0.36.0
ARG RUST_NIGHTLY_VERSION=2025-02-22
ARG JEMALLOC_VERSION=5.2.1
ARG JEMALLOC_CHECKSUM=34330e5ce276099e2e8950d9335db5a875689a4c6a56751ef3b1d8c537f887f6

# Legacy package versions (upgrade tests).
ARG LEGACY_GO_VERSION=1.20.2

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get upgrade -qq && apt-get install -qq \
    build-essential git gdb cmake clang-11 gcc-multilib \
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
    cargo install fortanix-sgx-tools && \
    cargo install sgxs-tools && \
    cargo install cargo-audit

# Install Go and utilities.
RUN wget https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz && \
    # Install legacy Go version.
    go install golang.org/dl/go${LEGACY_GO_VERSION}@latest && \
    go${LEGACY_GO_VERSION} download && \
    # Prepare folder for binaries.
    mkdir -p /go/bin && \
    # Install a specific version of protoc-gen-go.
    go install google.golang.org/protobuf/cmd/protoc-gen-go@v${GO_PROTOC_GEN_GO_VERSION} && \
    # Install golangci-lint from source because the binaries might not have been built
    # with the latest Go version, which is a problem when bumping Go.
    go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v${GOLANGCILINT_VERSION} && \
    # Install gocovmerge for e2e coverage.
    go install github.com/wadey/gocovmerge@${GOCOVMERGE_VERSION} && \
    # Install nancy for auditing dependencies.
    curl -sfL -o nancy https://github.com/sonatype-nexus-community/nancy/releases/download/v${GO_NANCY_VERSION}/nancy-v${GO_NANCY_VERSION}-linux-amd64 && \
    echo "${GO_NANCY_CHECKSUM} nancy" | sha256sum -c && \
    mv nancy /go/bin/nancy && \
    chmod +x /go/bin/nancy && \
    # Install gofumpt for code formatting.
    go install mvdan.cc/gofumpt@${GOFUMPT_VERSION} && \
    go install golang.org/x/tools/cmd/goimports@${GOIMPORTS_VERSION}

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
