#!/bin/sh -eu

usage() {
  echo >&2 "usage: $0 --node-address <node_address> --runtime-id <unused> --genesis-path <genesis_path>"
  exit 1
}

if [ "$1" = "--node-address" ]; then
  node_address=$2
else
  usage
fi
if [ "$5" = "--genesis-path" ]; then
  genesis_path=$6
else
  usage
fi

exec ./go/oasis-node/oasis-node debug txsource \
  --workload transfer \
  --address "$node_address" \
  --debug.allow_test_keys \
  --debug.dont_blame_oasis \
  --debug.test_entity \
  --genesis.file "$genesis_path" \
  --log.format JSON \
  --log.level DEBUG
