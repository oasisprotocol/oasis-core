#!/bin/bash

############################################################
# This script tests the Oasis Core project upgrades.
#
# Usage:
# test_upgrade.sh
############################################################

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

# Branches to test.
pre_upgrade_git_branch="stable/22.2.x"
post_upgrade_git_branch="master"

# Working directories.
workdir=$PWD
tmpdir=${TEST_BASE_DIR:-"/tmp"}
pre_upgrade_datadir="${tmpdir}/oasis-pre-upgrade"
post_upgrade_datadir="${tmpdir}/oasis-post-upgrade"

# Remove old data.
echo "Removing old data..."

rm -rf "${pre_upgrade_datadir}"
mkdir -p "${pre_upgrade_datadir}/e2e"

rm -rf "${post_upgrade_datadir}"
mkdir -p "${post_upgrade_datadir}/e2e"

# Download and build both branches.
echo "Downloading and building oasis-core ${pre_upgrade_git_branch} branch"

git clone https://github.com/oasisprotocol/oasis-core -b "${pre_upgrade_git_branch}" "${pre_upgrade_datadir}/oasis-core"
pushd "${pre_upgrade_datadir}/oasis-core"
    OASIS_GO=go1.19.10 make
popd

echo "Downloading and building oasis-core ${post_upgrade_git_branch} branch"

git clone https://github.com/oasisprotocol/oasis-core -b "${post_upgrade_git_branch}" "${post_upgrade_datadir}/oasis-core"
pushd "${post_upgrade_datadir}/oasis-core"
    make
popd

# Build test runners (Buildkite will fetch them as artifacts).
if [[ "${BUILDKITE:-""}" == "" ]]; then
    echo "Building pre/post upgrade test runners..."

    pushd "$workdir/tests/upgrade"
        make
    popd
fi

# Ensure binaries exist.
pre_upgrade_node_binary="${pre_upgrade_datadir}/oasis-core/go/oasis-node/oasis-node"
post_upgrade_node_binary="${post_upgrade_datadir}/oasis-core/go/oasis-node/oasis-node"

pre_upgrade_test_runner_binary="${workdir}/tests/upgrade/pre/oasis-test-pre-upgrade"
post_upgrade_test_runner_binary="${workdir}/tests/upgrade/post/oasis-test-post-upgrade"

if [[ ! -f "$pre_upgrade_node_binary" ]]; then
	echo "Binary $pre_upgrade_node_binary does not exist"
	exit 1
fi
if [[ ! -f "$pre_upgrade_test_runner_binary" ]]; then
	echo "Binary $pre_upgrade_test_runner_binary does not exist"
	exit 1
fi
if [[ ! -f "$post_upgrade_node_binary" ]]; then
	echo "Binary $post_upgrade_node_binary does not exist"
	exit 1
fi
if [[ ! -f "$post_upgrade_test_runner_binary" ]]; then
	echo "Binary $post_upgrade_test_runner_binary does not exist"
	exit 1
fi

# Mock IAS service.
ias_mock="true"
set +x
if [[ ${OASIS_IAS_APIKEY:-""} != "" ]]; then
    set -x
    ias_mock="false"
fi
set -x

# Extract the protocol versions required for the upgrade.
protocol_versions=$(${post_upgrade_node_binary} -v \
    | awk -F ' ' '/Consensus protocol version|Host protocol version|Committee protocol version/ {print $NF}' \
    | paste -sd ",")

# Run Oasis test runner.
echo "Starting pre-upgrade tests..."

${pre_upgrade_test_runner_binary} \
    --basedir ${pre_upgrade_datadir} \
    --basedir.no_cleanup \
    --basedir.no_temp_dir \
    --e2e.node.binary ${pre_upgrade_node_binary} \
    --e2e/runtime.runtime.binary_dir.default ${pre_upgrade_datadir}/oasis-core/target/default/debug \
    --e2e/runtime.runtime.binary_dir.intel-sgx ${pre_upgrade_datadir}/oasis-core/target/sgx/x86_64-fortanix-unknown-sgx/debug \
    --e2e/runtime.runtime.source_dir ${pre_upgrade_datadir}/oasis-core/tests/runtimes \
    --e2e/runtime.runtime.target_dir ${pre_upgrade_datadir}/oasis-core/target \
    --e2e/runtime.runtime.loader ${pre_upgrade_datadir}/oasis-core/target/default/debug/oasis-core-runtime-loader \
    --e2e/runtime.tee_hardware ${OASIS_TEE_HARDWARE:-""} \
    --e2e/runtime.ias.mock=${ias_mock} \
    --upgrade.protocol_versions=${protocol_versions} \
    --log.level debug \
    "$@"

# Copy state.
echo "Copying pre-upgrade test directories..."

cp -r ${pre_upgrade_datadir}/e2e/. ${post_upgrade_datadir}/e2e

# Run Oasis test runner.
echo "Starting post-upgrade tests..."

${post_upgrade_test_runner_binary} \
    --basedir ${post_upgrade_datadir} \
    --basedir.no_cleanup \
    --basedir.no_temp_dir \
    --e2e.node.binary ${post_upgrade_node_binary} \
    --e2e/runtime.runtime.binary_dir.default ${post_upgrade_datadir}/oasis-core/target/default/debug \
    --e2e/runtime.runtime.binary_dir.intel-sgx ${post_upgrade_datadir}/oasis-core/target/sgx/x86_64-fortanix-unknown-sgx/debug \
    --e2e/runtime.runtime.source_dir ${post_upgrade_datadir}/oasis-core/tests/runtimes \
    --e2e/runtime.runtime.target_dir ${post_upgrade_datadir}/oasis-core/target \
    --e2e/runtime.runtime.loader ${post_upgrade_datadir}/oasis-core/target/default/debug/oasis-core-runtime-loader \
    --e2e/runtime.tee_hardware ${OASIS_TEE_HARDWARE:-""} \
    --e2e/runtime.ias.mock=${ias_mock} \
    --scenario_timeout 1h \
    --log.level debug \
    "$@"
