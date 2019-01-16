# TODO: add arg to override this default image
FROM oasislabs/development:0.2.0 as builder

# Add metadata identifying this image as an
# intermediate build image so that we can
# clean it up from our host after a successful
# build. Remember, this intermediate image will
# contain the private SSH key! Best to not
# leave those images lying around where they can
# be forgotten about and lost track of.
LABEL stage=builder

WORKDIR /workdir

# Take an SSH key as a build argument.
ARG SSH_PRIVATE_KEY
# Take commit SHA as build argument.
ARG EKIDEN_COMMIT_SHA
# Take SGX mode as build argument.
ARG SGX_MODE=SIM
# Take AVR verification as build argument.
ARG EKIDEN_UNSAFE_SKIP_AVR_VERIFY=1
# Take Intel SGX SDK path as build argument.
ARG INTEL_SGX_SDK=/opt/sgxsdk

# 1. Create the SSH directory.
# 2. Populate the private key file.
# 3. Set the required permissions.
# 4. Add github to our list of known hosts for ssh.
RUN mkdir -p /root/.ssh/ && \
    echo "$SSH_PRIVATE_KEY" > /root/.ssh/id_rsa && \
    chmod -R 600 /root/.ssh/ && \
    ssh-keyscan -t rsa github.com >> ~/.ssh/known_hosts

# 1. Setup ssh-agent env
# 2. Add ssh identity at /root/.ssh/id_rsa
# 3. Tell git to use SSH instead of HTTPS so
#    that we can use the SSH identity when
#    checking out private repos.
# 4. Checkout the runtime-ethereum repo
#
# TODO: Add arg to specify which branch or commit sha should be checked out.
# TODO: Update the git clone command to do a shallow checkout. We only need
#       the latest source to build an image.
RUN eval $(ssh-agent -s) && \
    ssh-add && \
    git config --global url."ssh://git@github.com".insteadOf "https://github.com" && \
    git clone https://github.com/oasislabs/ekiden && \
    cd ekiden && \
    git checkout ${EKIDEN_COMMIT_SHA}

# Install ekiden-tools
RUN eval $(ssh-agent -s) && \
    ssh-add && \
    git config --global url."ssh://git@github.com".insteadOf "https://github.com" && \
    cd ekiden && \
    cargo install --force --path tools

# Build the worker, compute node and key manager
RUN eval $(ssh-agent -s) && \
    ssh-add && \
    git config --global url."ssh://git@github.com".insteadOf "https://github.com" && \
    cd ekiden && \
    make -C go && \
    cargo build -p ekiden-worker --release && \
    cargo build -p ekiden-keymanager-node --release && \
    cd key-manager/dummy/enclave && \
    cargo ekiden build-enclave --output-identity --release

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

COPY --from=builder /workdir/ekiden/go/ekiden/ekiden /ekiden/bin/ekiden-node
COPY --from=builder /workdir/ekiden/target/release/ekiden-worker /ekiden/bin/
COPY --from=builder /workdir/ekiden/target/release/ekiden-keymanager-node /ekiden/bin/
COPY --from=builder /workdir/ekiden/target/enclave/ekiden-keymanager-trusted.so /ekiden/lib/
COPY --from=builder /workdir/ekiden/target/enclave/ekiden-keymanager-trusted.mrenclave /ekiden/res/

ENV PATH "/ekiden/bin:${PATH}"
