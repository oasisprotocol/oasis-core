FROM ubuntu:18.04

# Package versions.
ARG GO_VERSION=1.15.1
ARG GO_PROTOC_VERSION=3.6.1
ARG GO_PROTOC_GEN_GO_VERSION=1.21.0
ARG GOLANGCILINT_VERSION=1.28.2
ARG GOCOVMERGE_VERSION=b5bfa59ec0adc420475f97f89b58045c721d761c
ARG GOFUMPT_VERSION=abc0db2c416aca0f60ea33c23c76665f6e7ba0b6
ARG RUST_NIGHTLY_VERSION=2020-08-29

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
    curl -sfL -o nancy https://github.com/sonatype-nexus-community/nancy/releases/download/v0.0.39/nancy-linux.amd64-v0.0.39 && \
    echo 'eb3a93d7db24d115e6e67a2b17dba402978f856c891fa6f0ff09ad17ac53ebb5 nancy' | sha256sum -c && \
    mv nancy /go/bin/nancy && \
    chmod +x /go/bin/nancy && \
    # Install gofumpt for code formatting.
    GO111MODULE=on go get mvdan.cc/gofumpt@${GOFUMPT_VERSION} && \
    GO111MODULE=on go get mvdan.cc/gofumpt/gofumports@${GOFUMPT_VERSION}

# Install bubblewrap (we need version 0.3.3 which is not available for 18.04).
RUN wget http://archive.ubuntu.com/ubuntu/pool/main/b/bubblewrap/bubblewrap_0.3.3-2_amd64.deb && \
    echo '1cf9bdae5cfab75f292fad9ee0ef76a7c55243dbc0515709624b2a9573d19447 bubblewrap_0.3.3-2_amd64.deb' | sha256sum -c && \
    dpkg -i bubblewrap_0.3.3-2_amd64.deb && \
    rm bubblewrap_0.3.3-2_amd64.deb
