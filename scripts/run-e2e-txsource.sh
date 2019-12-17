#!/bin/sh
# (no merge)
./go/oasis-test-runner/oasis-test-runner \
    --basedir.no_cleanup \
    --e2e.node.binary go/oasis-node/oasis-node \
    --e2e.client.binary_dir scripts \
    --e2e.runtime.binary_dir target/debug \
    --e2e.runtime.loader target/debug/oasis-core-runtime-loader \
    --log.level info \
    -t txsource
