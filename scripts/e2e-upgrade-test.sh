#!/bin/bash
set -euo pipefail -o errexit -x

# Kill all dangling processes on exit.
cleanup() {
	pkill -P $$ || true
	wait || true
}
trap "cleanup" EXIT

DATADIR="/tmp/oasis-upgrade-test"

# Environment variables.
PRE_UPGRADE_NET_RUNNER_BINARY=${PRE_UPGRADE_NET_RUNNER_BINARY:-}
PRE_UPGRADE_OASIS_NODE_BINARY=${PRE_UPGRADE_OASIS_NODE_BINARY:-}
PRE_UPGRADE_RUNTIME_LOADER_BINARY=${PRE_UPGRADE_RUNTIME_LOADER_BINARY:-}

POST_UPGRADE_OASIS_NODE_BINARY=${POST_UPGRADE_OASIS_NODE_BINARY:-}
POST_UPGRADE_NET_RUNNER_BINARY=${POST_UPGRADE_NET_RUNNER_BINARY:-}
POST_UPGRADE_RUNTIME_LOADER_BINARY=${POST_UPGRADE_RUNTIME_LOADER_BINARY:-}

UPGRADE_HELPER_BINARY=${UPGRADE_HELPER_BINARY:-}

KEYMANAGER_RUNTIM=${KEYMANAGER_BINARY:-}
KEYVALUE_RUNTIME=${KEYVALUE_BINARY:-}

# Ensure that environment variables are set and binaries exist.
if [[ -z "$PRE_UPGRADE_NET_RUNNER_BINARY" ]]; then
	echo "PRE_UPGRADE_NET_RUNNER_BINARY is not set"
	exit 1
fi
if [[ ! -f "$PRE_UPGRADE_NET_RUNNER_BINARY" ]]; then
	echo "PRE_UPGRADE_NET_RUNNER_BINARY does not exist"
	exit 1
fi
if [[ -z "$PRE_UPGRADE_OASIS_NODE_BINARY" ]]; then
	echo "PRE_UPGRADE_OASIS_NODE_BINARY is not set"
	exit 1
fi
if [[ ! -f "$PRE_UPGRADE_OASIS_NODE_BINARY" ]]; then
	echo "PRE_UPGRADE_OASIS_NODE_BINARY does not exist"
	exit 1
fi
if [[ -z "$PRE_UPGRADE_RUNTIME_LOADER_BINARY" ]]; then
	echo "PRE_UPGRADE_RUNTIME_LOADER_BINARY is not set"
	exit 1
fi
if [[ ! -f "$PRE_UPGRADE_RUNTIME_LOADER_BINARY" ]]; then
	echo "PRE_UPGRADE_RUNTIME_LOADER_BINARY does not exist"
	exit 1
fi
if [[ -z "$POST_UPGRADE_OASIS_NODE_BINARY" ]]; then
	echo "POST_UPGRADE_OASIS_NODE_BINARY is not set"
	exit 1
fi
if [[ ! -f "$POST_UPGRADE_OASIS_NODE_BINARY" ]]; then
	echo "POST_UPGRADE_OASIS_NODE_BINARY does not exist"
	exit 1
fi
if [[ -z "$POST_UPGRADE_NET_RUNNER_BINARY" ]]; then
	echo "POST_UPGRADE_NET_RUNNER_BINARY is not set"
	exit 1
fi
if [[ ! -f "$POST_UPGRADE_NET_RUNNER_BINARY" ]]; then
	echo "POST_UPGRADE_NET_RUNNER_BINARY does not exist"
	exit 1
fi
if [[ -z "$POST_UPGRADE_RUNTIME_LOADER_BINARY" ]]; then
	echo "POST_UPGRADE_RUNTIME_LOADER_BINARY is not set"
	exit 1
fi
if [[ ! -f "$POST_UPGRADE_RUNTIME_LOADER_BINARY" ]]; then
	echo "POST_UPGRADE_RUNTIME_LOADER_BINARY does not exist"
	exit 1
fi
if [[ -z "$UPGRADE_HELPER_BINARY" ]]; then
	echo "UPGRADE_HELPER_BINARY is not set"
	exit 1
fi
if [[ ! -f "$UPGRADE_HELPER_BINARY" ]]; then
	echo "UPGRADE_HELPER_BINARY does not exist"
	exit 1
fi

# Remove old data.
rm -rf "$DATADIR"
mkdir -p "$DATADIR"

# Prepare fixture.
$PRE_UPGRADE_NET_RUNNER_BINARY \
	dump-fixture \
	--fixture.default.deterministic_entities \
	--fixture.default.debug_test_entity=false \
	--fixture.default.num_entities 2 \
	--fixture.default.fund_entities \
	--fixture.default.node.binary "$PRE_UPGRADE_OASIS_NODE_BINARY" \
	--fixture.default.keymanager.binary "$KEYMANAGER_RUNTIME" \
	--fixture.default.runtime.binary "$KEYVALUE_RUNTIME" \
	--fixture.default.governance.upgrade_min_epoch_diff 10 \
	--fixture.default.governance.voting_period 2 \
	--fixture.default.epochtime_interval 20 \
	>"$DATADIR/pre-upgrade-fixture.json"

# Start the pre-upgrade network.
echo "Starting pre-upgrade network..."

$PRE_UPGRADE_NET_RUNNER_BINARY \
	--basedir "$DATADIR" \
	--basedir.no_cleanup \
	--basedir.no_temp_dir \
	--fixture.file "$DATADIR/pre-upgrade-fixture.json" &
RUNNER_PID=$!

sleep 5
# Run some tests.
# TODO: Run some tests here.
# TODO: Configurable time to run (e.g. until some block height is reached).

# Submit and vote for governance upgrade proposal to halt the network.
$UPGRADE_HELPER_BINARY perform-upgrade \
	--network_datadir "$DATADIR/net-runner/network" \
	--sock "$DATADIR/net-runner/network/client-0/internal.sock"

echo "Wait for network to halt..."
wait $RUNNER_PID

# Fix exported genesis.
EXPORTED_GENESIS=("$DATADIR"/net-runner/network/client-0/exports/genesis-*json)

mkdir -p "$DATADIR/post-upgrade"
FIXED_GENESIS="$DATADIR/post-upgrade/genesis.json"

$POST_UPGRADE_OASIS_NODE_BINARY \
	debug fix-genesis \
	--debug.dont_blame_oasis \
	--genesis.file "${EXPORTED_GENESIS[@]}" \
	--genesis.new_file "$FIXED_GENESIS"

# Copy state.
cp -r "$DATADIR/net-runner" "$DATADIR/post-upgrade/"
# Update datadir.
DATADIR="$DATADIR/post-upgrade"

# Reset consensus state on all nodes.
$UPGRADE_HELPER_BINARY reset-state \
	--network_datadir "$DATADIR/net-runner/network" \
	--oasis_node "$POST_UPGRADE_OASIS_NODE_BINARY"

# Prepare post-upgrade fixture.
$POST_UPGRADE_NET_RUNNER_BINARY \
	dump-fixture \
	--fixture.default.deterministic_entities \
	--fixture.default.restore_identities \
	--fixture.default.debug_test_entity=false \
	--fixture.default.num_entities 2 \
	--fixture.default.node.binary "$POST_UPGRADE_OASIS_NODE_BINARY" \
	--fixture.default.keymanager.binary "$KEYMANAGER_RUNTIME" \
	--fixture.default.runtime.binary "$KEYVALUE_RUNTIME" \
	--fixture.default.governance.upgrade_min_epoch_diff 10 \
	--fixture.default.governance.voting_period 2 \
	--fixture.default.epochtime_interval 20 \
	--fixture.default.genesis "$FIXED_GENESIS" \
	>"$DATADIR/post-upgrade-fixture.json"

# Start the post-upgrade network.
$POST_UPGRADE_NET_RUNNER_BINARY \
	--basedir "$DATADIR" \
	--basedir.no_cleanup \
	--basedir.no_temp_dir \
	--fixture.file "$DATADIR/post-upgrade-fixture.json" &

# TODO: Run some tests, continue running optionally.

sleep 10000
