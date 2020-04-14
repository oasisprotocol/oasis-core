FROM oasislabs/development:0.3.0

RUN apt-get install -y \
    unzip jq \
    libcurl4-openssl-dev zlib1g-dev libdw-dev libiberty-dev

# Install codecov for coverage.
RUN wget -O codecov https://codecov.io/bash && \
    chmod +x codecov && \
    mv codecov /usr/local/bin

# Install tarpaulin.
RUN RUSTFLAGS="--cfg procmacro2_semver_exempt" \
    cargo install --version 0.9.1 cargo-tarpaulin
