#!/bin/bash -ex

# Our development image sets up the PATH in .bashrc. Source that.
PS1='\$'
. ~/.bashrc

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
(cd contracts/token && cargo ekiden build-enclave --release)
(cd compute && cargo build --release)

# Build all Ekiden Go binaries and resources.
GO_SRC_BASE=${GOPATH}/src/github.com/oasislabs
mkdir -p ${GO_SRC_BASE}
ln -s `pwd` ${GO_SRC_BASE}/ekiden
(cd ${GO_SRC_BASE}/ekiden/go && dep ensure)
(cd ${GO_SRC_BASE}/ekiden/go && go generate ./...)
(cd ${GO_SRC_BASE}/ekiden/go && go build -o ./ekiden/ekiden ./ekiden)

# Package all binaries and resources.
mkdir -p target/docker-deployment/context/bin target/docker-deployment/context/lib target/docker-deployment/context/res
ln target/enclave/token.so target/docker-deployment/context/lib
ln target/release/ekiden-compute target/docker-deployment/context/bin
ln go/ekiden/ekiden target/docker-deployment/context/bin/ekiden-node
if [ -e docker/deployment/Dockerfile.generated ]
then
    ln docker/deployment/Dockerfile.generated target/docker-deployment/context/Dockerfile
else
    ln docker/deployment/Dockerfile.runtime target/docker-deployment/context/Dockerfile
fi
tar cvzhf target/docker-deployment/context.tar.gz -C target/docker-deployment/context .
rm -rf target/docker-deployment/context
