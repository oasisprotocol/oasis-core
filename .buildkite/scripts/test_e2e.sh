#!/bin/bash

############################################################
# This script tests the Oasis Core project.
#
# Usage:
# test_e2e.sh
############################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

# Working directory.
WORKDIR=$PWD

#################
# Run test suite.
#################
# Determine correct runtime to use for SGX.
runtime_target="."
runtime_ext=""
if [[ "${OASIS_TEE_HARDWARE:-""}" == "intel-sgx" ]]; then
    runtime_target="x86_64-fortanix-unknown-sgx"
    runtime_ext=".sgxs"
fi

# We need a directory in the workdir so that Buildkite can fetch artifacts.
if [[ "${BUILDKITE:-""}" != "" ]]; then
    mkdir -p ${WORKDIR}/e2e
fi

# Run Oasis test runner.
${WORKDIR}/go/oasis-test-runner/oasis-test-runner \
    ${BUILDKITE:+--basedir ${WORKDIR}/e2e} \
    --basedir.no_cleanup \
    --e2e.node.binary ${WORKDIR}/go/oasis-node/oasis-node \
    --e2e.client.binary_dir ${WORKDIR}/target/debug \
    --e2e.keymanager.binary ${WORKDIR}/target/${runtime_target}/debug/oasis-core-keymanager-runtime${runtime_ext} \
    --e2e.runtime.binary ${WORKDIR}/target/${runtime_target}/debug/simple-keyvalue${runtime_ext} \
    --e2e.runtime.loader ${WORKDIR}/target/debug/oasis-core-runtime-loader \
    --e2e.tee_hardware ${OASIS_TEE_HARDWARE:-""} \
    --log.level info \
    ${BUILDKITE_PARALLEL_JOB_COUNT:+--parallel.job_count ${BUILDKITE_PARALLEL_JOB_COUNT}} \
    ${BUILDKITE_PARALLEL_JOB:+--parallel.job_index ${BUILDKITE_PARALLEL_JOB}} \
    "$@"
