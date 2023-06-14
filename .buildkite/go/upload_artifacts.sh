#!/bin/bash

set -euxo pipefail

# Oasis node, test runner, remote signer and runtime loader.
pushd /workdir/go/oasis-node
    buildkite-agent artifact upload oasis-node
    buildkite-agent artifact upload oasis-node.test
popd

pushd /workdir/go/oasis-test-runner
    buildkite-agent artifact upload oasis-test-runner
    buildkite-agent artifact upload oasis-test-runner.test
popd

pushd /workdir/go/oasis-remote-signer
    buildkite-agent artifact upload oasis-remote-signer
popd

pushd /workdir/go/oasis-test-runner/scenario/pluginsigner/example_signer_plugin
    buildkite-agent artifact upload example_signer_plugin
popd

# Net runner.
pushd /workdir/go/oasis-net-runner
    buildkite-agent artifact upload oasis-net-runner
popd

# Upgrade test runners.
pushd /workdir/tests/upgrade/pre
    buildkite-agent artifact upload oasis-test-pre-upgrade
popd

pushd /workdir/tests/upgrade/post
    buildkite-agent artifact upload oasis-test-post-upgrade
popd