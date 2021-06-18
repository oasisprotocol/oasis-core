FROM docker.io/tozd/sgx:ubuntu-bionic

# Runtime dependencies
RUN apt-get install -qq libsnappy1v5 librocksdb5.8 && \
    wget http://archive.ubuntu.com/ubuntu/pool/main/b/bubblewrap/bubblewrap_0.4.1-1_amd64.deb && \
    echo '25de452f209e4fdb4b009851c33ca9a0269ebf0b92f4bd9b86186480592cc3e2 bubblewrap_0.4.1-1_amd64.deb' | sha256sum -c && \
    dpkg -i bubblewrap_0.4.1-1_amd64.deb && \
    rm bubblewrap_0.4.1-1_amd64.deb

# Core
COPY go/oasis-node/oasis-node 				/oasis/bin/
COPY go/oasis-net-runner/oasis-net-runner 		/oasis/bin/
COPY go/oasis-remote-signer/oasis-remote-signer 	/oasis/bin/

# Example runtimes
COPY target/default/debug/oasis-core-runtime-loader 	/oasis/bin/
COPY target/default/debug/simple-keymanager* 		/oasis/bin/
COPY target/default/debug/simple-keyvalue* 		/oasis/bin/

ENV PATH "/oasis/bin:${PATH}"
