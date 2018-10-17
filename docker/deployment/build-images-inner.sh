#!/bin/bash -e

# Our development image sets up the PATH in .bashrc. Source that.
PS1='\$'
. ~/.bashrc
set -x

# Abort on unclean packaging area.
if [ -e target/docker-deployment/context ]; then
    cat >&2 <<EOF
Path target/docker-deployment/context already exists. Aborting.
If this was accidentally left over and you don't need anything from
it, you can remove it and try again.
EOF
    exit 1
fi

# Build all Ekiden Rust binaries and resources.
cargo install --force --path tools
(cd compute && cargo build --release)
(cd key-manager/node && cargo build --release)
(cd key-manager/dummy/enclave && cargo ekiden build-enclave --output-identity --release)

# Build all Ekiden Go binaries and resources.
GO_SRC_BASE=${GOPATH}/src/github.com/oasislabs
mkdir -p ${GO_SRC_BASE}
ln -sfT `pwd` ${GO_SRC_BASE}/ekiden
(cd ${GO_SRC_BASE}/ekiden/go && dep ensure -v)
(cd ${GO_SRC_BASE}/ekiden/go && go generate ./...)
(cd ${GO_SRC_BASE}/ekiden/go && go build -o ./ekiden/ekiden ./ekiden)

# Package all binaries and resources.
mkdir -p target/docker-deployment/context/bin target/docker-deployment/context/lib target/docker-deployment/context/res
ln target/release/ekiden-compute target/docker-deployment/context/bin
ln go/ekiden/ekiden target/docker-deployment/context/bin/ekiden-node
ln target/release/ekiden-keymanager-node target/docker-deployment/context/bin
ln target/enclave/ekiden-keymanager-trusted.so target/docker-deployment/context/lib
ln target/enclave/ekiden-keymanager-trusted.mrenclave target/docker-deployment/context/res
if [ -e docker/deployment/Dockerfile.generated ]
then
    ln docker/deployment/Dockerfile.generated target/docker-deployment/context/Dockerfile
else
    ln docker/deployment/Dockerfile.runtime target/docker-deployment/context/Dockerfile
fi
tar cvzhf target/docker-deployment/context.tar.gz -C target/docker-deployment/context .
rm -rf target/docker-deployment/context
