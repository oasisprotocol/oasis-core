FROM docker.io/ekiden/rust-sgx-sdk:0.9.7

ENV HOME="/root"
ENV PATH="${HOME}/.cargo/bin:${PATH}"

RUN apt-get update -q -q && \
    apt-get install -y pkg-config python-pyelftools golang && \
    rustup install nightly-2018-02-05 && \
    rustup default nightly-2018-02-05 && \
    cargo install rustfmt-nightly --version 0.3.6 --force
