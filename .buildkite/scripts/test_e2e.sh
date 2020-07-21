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

node_binary="${WORKDIR}/go/oasis-node/oasis-node"
test_runner_binary="${WORKDIR}/go/oasis-test-runner/oasis-test-runner"
skip_options=""

# Use e2e-coverage-wrapper.sh as node binary if we need to compute E2E
# tests' coverage.
if [[ ${OASIS_E2E_COVERAGE:-""} != "" ]]; then
    test_runner_binary="${WORKDIR}/scripts/e2e-coverage-wrapper-arg.sh ${test_runner_binary}.test"

    # Use -env version of the wrapper as we can't pass additional arguments there.
    export E2E_COVERAGE_BINARY=${node_binary}.test
    node_binary="${WORKDIR}/scripts/e2e-coverage-wrapper-env.sh"

    # The runtime library's "different version" detection also freaks out
    # if build flags changes, and as far as I can tell --covermode doesn't
    # work.
    skip_options="--skip plugin-signer/basic"
fi

ias_mock="true"
set +x
if [[ ${OASIS_IAS_APIKEY:-""} != "" ]]; then
    set -x
    ias_mock="false"
fi
set -x

# Run Oasis test runner.
${test_runner_binary} \
    ${BUILDKITE:+--basedir ${TEST_BASE_DIR:-$PWD}/e2e} \
    --basedir.no_cleanup \
    --e2e.node.binary ${node_binary} \
    --e2e/runtime.client.binary_dir ${WORKDIR}/target/default/debug \
    --e2e/runtime.runtime.binary_dir ${WORKDIR}/target/${runtime_target}/debug \
    --e2e/runtime.runtime.loader ${WORKDIR}/target/default/debug/oasis-core-runtime-loader \
    --e2e/runtime.tee_hardware ${OASIS_TEE_HARDWARE:-""} \
    --e2e/runtime.ias.mock=${ias_mock} \
    --remote-signer.binary ${WORKDIR}/go/oasis-remote-signer/oasis-remote-signer \
    --plugin-signer.binary ${WORKDIR}/go/oasis-test-runner/scenario/pluginsigner/example_signer_plugin/example_signer_plugin.so \
    --log.level info \
    ${skip_options} \
    ${BUILDKITE_PARALLEL_JOB_COUNT:+--parallel.job_count ${BUILDKITE_PARALLEL_JOB_COUNT}} \
    ${BUILDKITE_PARALLEL_JOB:+--parallel.job_index ${BUILDKITE_PARALLEL_JOB}} \
    "$@"

# Gather the coverage output.
if [[ "${BUILDKITE:-""}" != "" ]]; then
    if [[ ${OASIS_E2E_COVERAGE:-""} != "" ]]; then
        hw_tag="${OASIS_TEE_HARDWARE:+-${OASIS_TEE_HARDWARE}}"
        step_tag="${BUILDKITE_STEP_KEY:+-${BUILDKITE_STEP_KEY}}"
        parallel_tag="-${BUILDKITE_PARALLEL_JOB:-0}"
        merged_file="coverage-merged-e2e${hw_tag}${step_tag}${parallel_tag}.txt"
        gocovmerge coverage-e2e-*.txt >"$merged_file"
    fi
fi
