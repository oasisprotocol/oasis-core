#!/bin/sh -eu

usage() {
  echo >&2 "usage: $0 --node-address <node_address> --runtime-id <unused> --genesis-path <genesis_path> --time-limit <time_limit>"
  #                0  1              2              3            4        5              6              7            8
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

if [ "$7" = "--time-limit" ]; then
  time_limit=$8
else
  usage
fi

exec ./go/oasis-node/oasis-node debug txsource \
  --workload transfer \
  --time_limit "$time_limit" \
  --address "$node_address" \
  --debug.allow_test_keys \
  --debug.dont_blame_oasis \
  --debug.test_entity \
  --genesis.file "$genesis_path" \
  --log.format JSON \
  --log.level DEBUG
