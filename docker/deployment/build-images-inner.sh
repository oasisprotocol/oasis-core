#!/bin/bash -e

# Our development image sets up the PATH in .bashrc. Source that.
PS1='\$'
. ~/.bashrc

# Abort on unclean packaging area.
if [ -e target/package ]; then
    cat >&2 <<EOF
Path target/package already exists. Aborting.
If this was accidentally left over and you don't need anything from
it, you can remove it and try again.
EOF
    exit 1
fi

# Build all Ekiden binaries and resources.
cargo install --force --path tools ekiden-tools
(cd contracts/key-manager && cargo ekiden build-contract --release)
(cd contracts/token && cargo ekiden build-contract --release)
(cd compute && cargo build --release)
(cd consensus && cargo build --release)

# Package all binaries and resources.
mkdir -p target/package/bin target/package/lib target/package/res
ln target/contract/ekiden-key-manager.so target/package/lib
ln target/contract/token.so target/package/lib
ln target/release/ekiden-compute target/package/bin
ln target/release/ekiden-consensus target/package/bin
ln docker/deployment/Dockerfile.runtime target/package/Dockerfile
tar cvzhf target/deployment.tar.gz -C target/package .
rm -rf target/package
