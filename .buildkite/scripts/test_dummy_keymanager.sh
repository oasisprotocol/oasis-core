#!/bin/bash

############################################################
# This script tests the Ekiden dummy key manager.
#
# Usage:
# test_dummy_keymanager.sh [-w <workdir>]
############################################################

# Defaults.
WORKDIR=$(pwd)

#########################
# Process test arguments.
#########################
while getopts 'f:t:' arg
do
    case ${arg} in
        w) WORKDIR=${OPTARG};;
        *)
            echo "Usage: $0 [-w <workdir>]"
            exit 1
    esac
done

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

source .buildkite/scripts/common.sh
source .buildkite/scripts/common_e2e.sh
source .buildkite/rust/common.sh

# Test the key manager node.
test_keymanager() {
    sleep 3

    ${WORKDIR}/target/debug/ekiden-keymanager-test-client \
        --mrenclave $(cat ${WORKDIR}/target/enclave/ekiden-keymanager-trusted.mrenclave) \
        --tls-certificate ${WORKDIR}/tests/keymanager/km.pem
}

# Test minimal configuration.
run_keymanager_node
test_keymanager
cleanup

# Test with provided internal keys.
run_keymanager_node --internal-keys "${WORKDIR}/tests/keymanager/internal-keys.cbor"
test_keymanager
cleanup
