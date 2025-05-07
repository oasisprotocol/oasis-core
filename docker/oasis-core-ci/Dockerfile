ARG OASIS_CORE_DEV_BASE_TAG=master

FROM ghcr.io/oasisprotocol/oasis-core-dev:${OASIS_CORE_DEV_BASE_TAG}

RUN apt-get install -y \
    unzip jq \
    libcurl4-openssl-dev zlib1g-dev libdw-dev libiberty-dev

# Install codecov for coverage.
RUN wget -O codecov https://codecov.io/bash && \
    chmod +x codecov && \
    mv codecov /usr/local/bin

# Install tarpaulin.
RUN cargo install --version 0.32.5 cargo-tarpaulin
