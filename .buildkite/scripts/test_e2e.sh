#!/bin/bash

############################################################
# This script tests the Ekiden project.
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
if [[ "${EKIDEN_TEE_HARDWARE:-""}" == "intel-sgx" ]]; then
    runtime_target="x86_64-fortanix-unknown-sgx"
    runtime_ext=".sgxs"
fi

# We need a directory in the workdir so that Buildkite can fetch artifacts.
mkdir -p ${WORKDIR}/e2e
# Run ekiden test runner.
${WORKDIR}/go/ekiden-test-runner/ekiden-test-runner \
    --basedir ${WORKDIR}/e2e \
    --basedir.no_cleanup \
    --e2e.ekiden.binary ${WORKDIR}/go/ekiden/ekiden \
    --e2e.client.binary_dir ${WORKDIR}/target/debug \
    --e2e.keymanager.binary ${WORKDIR}/target/${runtime_target}/debug/ekiden-keymanager-runtime${runtime_ext} \
    --e2e.runtime.binary ${WORKDIR}/target/${runtime_target}/debug/simple-keyvalue${runtime_ext} \
    --e2e.runtime.loader ${WORKDIR}/target/debug/ekiden-runtime-loader \
    --e2e.tee_hardware ${EKIDEN_TEE_HARDWARE:-""} \
    --log.level info \
    --parallel.job_count ${BUILDKITE_PARALLEL_JOB_COUNT} \
    --parallel.job_index ${BUILDKITE_PARALLEL_JOB}
