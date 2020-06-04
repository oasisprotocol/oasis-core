#!/bin/bash

cd
git clone https://github.com/oasisprotocol/oasis-core.git
cd oasis-core
make
SOURCE_DATE_EPOCH=`git log -1 --format=%ai $IMG_VER`
tar --sort=name \
      --mtime="${SOURCE_DATE_EPOCH}" \
      --owner=0 --group=0 --numeric-owner \
      --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
      -cvf oasis_core_reproducible_${IMG_VER}_linux_amd64.tar.gz \
      go/oasis-node/oasis-node \
      go/oasis-net-runner/oasis-net-runner \
      target/debug/oasis-core-runtime-loader \
      target/sgx/x86_64-fortanix-unknown-sgx/debug/simple-keyvalue.sgxs

