#!/bin/bash

############################################################
# This script tests the Ekiden project.
#
# Usage:
# test_e2e.sh [-w <workdir>] [-t <test-name>]
############################################################

# Defaults.
WORKDIR=$(pwd)
TEST_FILTER=""

#########################
# Process test arguments.
#########################
while getopts 'f:t:' arg
do
    case ${arg} in
        w) WORKDIR=${OPTARG};;
        t) TEST_FILTER=${OPTARG};;
        *)
            echo "Usage: $0 [-w <workdir>] [-t <test-name>]"
            exit 1
    esac
done

# Helpful tips on writing build scripts:
# https://buildkite.com/docs/pipelines/writing-build-scripts
set -euxo pipefail

source .buildkite/scripts/common.sh
source .buildkite/scripts/common_e2e.sh
source .buildkite/rust/common.sh

###################
# Test definitions.
###################
scenario_basic() {
    local runtime=$1

    # Initialize compute nodes.
    run_compute_node 1 ${runtime}
    run_compute_node 2 ${runtime}
    run_compute_node 3 ${runtime}

    # Wait for all compute nodes to start.
    wait_compute_nodes 3

    # Advance epoch to elect a new committee.
    set_epoch 1
}

scenario_discrepancy() {
    local runtime=$1

    # Initialize compute nodes.
    run_compute_node 1 ${runtime} \
        --worker.byzantine.inject_discrepancies

    run_compute_node 2 ${runtime}
    run_compute_node 3 ${runtime}

    # Wait for all compute nodes to start.
    wait_compute_nodes 3

    # Advance epoch to elect a new committee.
    set_epoch 1
}

#############
# Test suite.
#
# Arguments:
#    backend_name - name of the backend to use in test name
#    backend_runner - function that will prepare and run the backend services
#############
test_suite() {
    local backend_name=$1
    local backend_runner=$2

    # Basic scenario using the simple-keyvalue runtime and client.
    run_test \
        scenario=scenario_basic \
        name="e2e-${backend_name}-basic-full" \
        backend_runner=$backend_runner \
        runtime=simple-keyvalue \
        client=simple-keyvalue

    # Database encryption test.
    run_test \
        scenario=scenario_basic \
        name="e2e-${backend_name}-basic-enc" \
        backend_runner=$backend_runner \
        runtime=simple-keyvalue \
        client=simple-keyvalue-enc

    # Discrepancy scenario.
    run_test \
        scenario=scenario_discrepancy \
        name="e2e-${backend_name}-discrepancy" \
        backend_runner=$backend_runner \
        runtime=simple-keyvalue \
        client=simple-keyvalue \
        on_success_hook=assert_no_round_timeouts
}

##########################################
# Multiple validators tendermint backends.
##########################################
test_suite tm-committee run_backend_tendermint_committee
