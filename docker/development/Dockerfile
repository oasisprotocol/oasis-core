FROM docker.io/ekiden/rust-sgx-sdk:0.9.7

ENV HOME="/root"
ENV PATH="${HOME}/.cargo/bin:${PATH}"

RUN apt-get update -q -q && \
    apt-get install -y pkg-config python-pyelftools && \
    rustup update nightly && \
    cargo +nightly install rustfmt-nightly --version 0.3.6 --force && \
    cargo install cargo-make
