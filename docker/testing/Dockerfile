FROM oasislabs/development:0.2.0

RUN apt-get install -y \
    unzip jq \
    binutils-dev libcurl4-openssl-dev zlib1g-dev libdw-dev libiberty-dev \
    llvm-7 python3-pip

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

# Install tarpaulin.
RUN RUSTFLAGS="--cfg procmacro2_semver_exempt" \
    cargo install \
    --git https://github.com/oasislabs/tarpaulin \
    --branch oasis \
    cargo-tarpaulin

# Install TVM
RUN git clone --recursive https://github.com/dmlc/tvm.git /tmp/tvm && \
    cd /tmp/tvm && \
    git checkout f6be4d6 && \
    mkdir build && cd build && \
    cmake .. -DUSE_LLVM=ON && \
    make -j4 && cd ../nnvm && make -j4 && cd .. && \
    pip3 install -e python -e nnvm/python -e topi/python
