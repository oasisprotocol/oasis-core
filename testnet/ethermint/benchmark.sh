#!/bin/bash

# Helper function for running an Ekiden benchmark.
benchmark() {
    kubectl run ethermint-benchmark \
        --stdin \
        --rm \
        --command \
        --quiet \
        --image=ethereum/client-go:latest \
        --restart=Never \
        -- sh -c "
          cat > benchmark.js

          geth attach --exec \"loadScript('benchmark.js')\" http://ethermint-0.ethermint.default.svc.cluster.local:8545
        "
}

benchmark < benchmark.js
