FROM docker.io/tozd/sgx:ubuntu-bionic

RUN apt-get install -qq libsnappy1v5 librocksdb5.8 && \
    wget http://archive.ubuntu.com/ubuntu/pool/main/b/bubblewrap/bubblewrap_0.3.1-2_amd64.deb && \
    echo '348ff7e71cac05d9e8f154ecc24ad1c9461e76b4ff23e992dcb60f9da51247af bubblewrap_0.3.1-2_amd64.deb' | sha256sum -c && \
    dpkg -i bubblewrap_0.3.1-2_amd64.deb && \
    rm bubblewrap_0.3.1-2_amd64.deb

ARG EKIDEN_COMMIT_SHA
ARG EKIDEN_BUILD_IMAGE_TAG

LABEL com.oasislabs.ekiden-commit-sha="${EKIDEN_COMMIT_SHA}"
LABEL com.oasislabs.ekiden-build-image-tag="${EKIDEN_BUILD_IMAGE_TAG}"

COPY go/ekiden/ekiden /ekiden/bin/ekiden-node
COPY target/release/ekiden-worker /ekiden/bin/
COPY target/release/ekiden-keymanager-node /ekiden/bin/
COPY target/enclave/ekiden-keymanager-trusted.so /ekiden/lib/
COPY target/enclave/ekiden-keymanager-trusted.mrenclave /ekiden/res/

ENV PATH "/ekiden/bin:${PATH}"
