FROM docker.io/tozd/sgx:ubuntu-bionic

RUN apt-get install -qq libsnappy1v5 librocksdb5.8 && \
    wget http://archive.ubuntu.com/ubuntu/pool/main/b/bubblewrap/bubblewrap_0.3.3-2_amd64.deb && \
    echo '1cf9bdae5cfab75f292fad9ee0ef76a7c55243dbc0515709624b2a9573d19447 bubblewrap_0.3.3-2_amd64.deb' | sha256sum -c && \
    dpkg -i bubblewrap_0.3.3-2_amd64.deb && \
    rm bubblewrap_0.3.3-2_amd64.deb

ARG OASIS_CORE_COMMIT_SHA
ARG OASIS_CORE_BUILD_IMAGE_TAG

LABEL com.oasislabs.oasis-core-commit-sha="${OASIS_CORE_COMMIT_SHA}"
LABEL com.oasislabs.oasis-core-build-image-tag="${OASIS_CORE_BUILD_IMAGE_TAG}"

COPY go/oasis-node/oasis-node /oasis/bin/oasis-node
COPY target/release/oasis-core-runtime-loader /oasis/bin/
COPY target/release/oasis-core-keymanager-runtime /oasis/lib/
COPY target/x86_64-fortanix-unknown-sgx/release/oasis-core-keymanager-runtime.sgxs /oasis/lib/
COPY scripts/initialize-client.sh scripts/initialize-client.sh

ENV PATH "/oasis/bin:${PATH}"
