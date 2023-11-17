#!/bin/bash

############################################################
# This script tests the Oasis Core project key manager 
# upgrades.
#
# Usage:
# test_km_upgrade.sh
############################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

# Working directory.
WORKDIR=$PWD

# We need a directory in the workdir so that Buildkite can fetch artifacts.
if [[ "${BUILDKITE:-""}" != "" ]]; then
    mkdir -p ${TEST_BASE_DIR:-$PWD}/e2e
fi

node_binary="${WORKDIR}/go/oasis-node/oasis-node"
test_runner_binary="${WORKDIR}/go/oasis-test-runner/oasis-test-runner"

ias_mock="true"
set +x
if [[ ${OASIS_IAS_APIKEY:-""} != "" ]]; then
    set -x
    ias_mock="false"
fi
set -x

# Branch to test against.
git_branch="stable/22.2.x"

# Temporary directory for building the branch.
DATADIR=${TEST_BASE_DIR:-"/tmp"}/oasis-km-upgrade/oasis-core

# Remove old data.
echo "Removing old data..."

rm -rf "${DATADIR}"
mkdir -p "${DATADIR}"

# Download and build the branch.
echo "Downloading and building oasis-core ${git_branch} branch"

git clone https://github.com/oasisprotocol/oasis-core -b "${git_branch}" "${DATADIR}"
pushd "${DATADIR}"
    make build-tools build-runtimes build-rust
popd

# Run Oasis test runner.
${test_runner_binary} \
    ${BUILDKITE:+--basedir ${TEST_BASE_DIR:-$PWD}/e2e} \
    --basedir.no_cleanup \
    --e2e.node.binary ${node_binary} \
    --e2e/runtime.runtime.binary_dir.default ${DATADIR}/target/default/debug \
    --e2e/runtime.runtime.binary_dir.default.upgrade ${WORKDIR}/target/default/debug \
    --e2e/runtime.runtime.binary_dir.intel-sgx ${DATADIR}/target/sgx/x86_64-fortanix-unknown-sgx/debug \
    --e2e/runtime.runtime.binary_dir.intel-sgx.upgrade ${WORKDIR}/target/sgx/x86_64-fortanix-unknown-sgx/debug \
    --e2e/runtime.runtime.source_dir ${WORKDIR}/tests/runtimes \
    --e2e/runtime.runtime.target_dir ${WORKDIR}/target \
    --e2e/runtime.runtime.loader ${WORKDIR}/target/default/debug/oasis-core-runtime-loader \
    --e2e/runtime.tee_hardware ${OASIS_TEE_HARDWARE:-""} \
    --e2e/runtime.ias.mock=${ias_mock} \
    --remote-signer.binary ${WORKDIR}/go/oasis-remote-signer/oasis-remote-signer \
    --plugin-signer.name example \
    --plugin-signer.binary ${WORKDIR}/go/oasis-test-runner/scenario/pluginsigner/example_signer_plugin/example_signer_plugin \
    --log.level debug \
    "$@"
