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
runtime_target="default"
if [[ "${OASIS_TEE_HARDWARE:-""}" == "intel-sgx" ]]; then
    runtime_target="sgx/x86_64-fortanix-unknown-sgx"
fi

# We need a directory in the workdir so that Buildkite can fetch artifacts.
if [[ "${BUILDKITE:-""}" != "" ]]; then
    mkdir -p ${TEST_BASE_DIR:-$PWD}/e2e
fi

# Use integrationrunner-wrapper.sh as node binary if we need to compute E2E
# tests' coverage.
node_binary="${WORKDIR}/go/oasis-node/oasis-node"
if [[ ${OASIS_E2E_COVERAGE:-""} != "" ]]; then
    node_binary="${WORKDIR}/scripts/integrationrunner-wrapper.sh"
fi

# Run Oasis test runner.
${WORKDIR}/go/oasis-test-runner/oasis-test-runner \
    ${BUILDKITE:+--basedir ${TEST_BASE_DIR:-$PWD}/e2e} \
    --basedir.no_cleanup \
    --e2e.node.binary ${node_binary} \
    --e2e.client.binary_dir ${WORKDIR}/target/default/debug \
    --e2e.runtime.binary_dir ${WORKDIR}/target/${runtime_target}/debug \
    --e2e.runtime.loader ${WORKDIR}/target/default/debug/oasis-core-runtime-loader \
    --e2e.tee_hardware ${OASIS_TEE_HARDWARE:-""} \
    --log.level info \
    ${BUILDKITE_PARALLEL_JOB_COUNT:+--parallel.job_count ${BUILDKITE_PARALLEL_JOB_COUNT}} \
    ${BUILDKITE_PARALLEL_JOB:+--parallel.job_index ${BUILDKITE_PARALLEL_JOB}} \
    "$@"

# Gather the coverage output.
if [[ "${BUILDKITE:-""}" != "" ]]; then
    if [[ ${OASIS_E2E_COVERAGE:-""} != "" ]]; then
        if [[ "${OASIS_TEE_HARDWARE:-""}" == "intel-sgx" ]]; then
            tar -zvcf coverage-e2e-sgx-${BUILDKITE_PARALLEL_JOB}.tar.gz coverage-e2e-*.txt
        else
            tar -zvcf coverage-e2e-${BUILDKITE_PARALLEL_JOB}.tar.gz coverage-e2e-*.txt
        fi
    fi
fi
