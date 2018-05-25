FROM docker.io/ekiden/development:0.1.0

# This is the release of tendermint to pull in.
ENV TM_VERSION 0.13.0
ENV TM_SHA256SUM 36d773d4c2890addc61cc87a72c1e9c21c89516921b0defb0edfebde719b4b85

# Tendermint will be looking for genesis file in /tendermint (unless you change
# `genesis_file` in config.toml). You can put your config.toml and private
# validator file into /tendermint.
#
# The /tendermint/data dir is used by tendermint to store state.
ENV DATA_ROOT /tendermint
ENV TMHOME $DATA_ROOT

# Set user right away for determinism
RUN adduser --system --group tmuser

# Create directory for persistence and give our user ownership
RUN mkdir -p $DATA_ROOT && \
    chown -R tmuser:tmuser $DATA_ROOT

# jq and curl used for extracting `pub_key` from private validator while
# deploying tendermint with Kubernetes. unzip for extracting tendermint.
# Install dependencies for kcov <https://github.com/SimonKagstrom/kcov/blob/master/INSTALL.md>.
RUN apt-get install -y \
    unzip jq \
    binutils-dev libcurl4-openssl-dev zlib1g-dev libdw-dev libiberty-dev

RUN wget https://s3-us-west-2.amazonaws.com/tendermint/binaries/tendermint/v${TM_VERSION}/tendermint_${TM_VERSION}_linux_amd64.zip && \
    echo "${TM_SHA256SUM}  tendermint_${TM_VERSION}_linux_amd64.zip" | sha256sum -c && \
    unzip -d /bin tendermint_${TM_VERSION}_linux_amd64.zip && \
    rm -f tendermint_${TM_VERSION}_linux_amd64.zip

# Leave $DATA_ROOT in the ephemeral filesystem so that we start tests with a clean state.

# Don't expose services from testing instance.

# Install Docker client for building testnet images.
RUN VER="18.03.0-ce" && \
    curl -L -o /tmp/docker-$VER.tgz https://download.docker.com/linux/static/stable/x86_64/docker-$VER.tgz && \
    tar -xz -C /tmp -f /tmp/docker-$VER.tgz && \
    rm /tmp/docker-$VER.tgz && \
    mv /tmp/docker/* /usr/bin

# Install kubectl for deployment.
RUN VERSION="v1.10.0" && \
    curl -LO https://storage.googleapis.com/kubernetes-release/release/$VERSION/bin/linux/amd64/kubectl && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/kubectl

# Install kcov for coverage.
RUN VERSION="35" && \
    wget -O /tmp/kcov-v$VERSION.tar.gz https://github.com/SimonKagstrom/kcov/archive/v$VERSION.tar.gz && \
    tar -xf /tmp/kcov-v$VERSION.tar.gz -C /tmp && \
    mkdir /tmp/kcov-$VERSION/build && \
    cd /tmp/kcov-$VERSION/build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make && \
    make install && \
    cd ../.. && \
    rm -r kcov-v$VERSION.tar.gz kcov-$VERSION

# Install codecov for coverage.
RUN wget -O codecov https://codecov.io/bash && \
    chmod +x codecov && \
    mv codecov /usr/local/bin
