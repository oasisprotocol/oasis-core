#!/bin/sh -eu

usage() {
  echo >&2 "usage: $0 --node-address <node_address> --runtime-id <unused> --node-binary <node_binary> -- <txsource args ...>"
  #                0  1              2              3            4        5             6             7
  exit 1
}

if [ "$1" = "--node-address" ]; then
  node_address=$2
else
  usage
fi
if [ "$5" = "--node-binary" ]; then
  node_binary=$6
else
  usage
fi
if [ "$7" = "--" ]; then
  shift 7
else
  usage
fi

exec "$node_binary" debug txsource \
  --address "$node_address" \
  "$@"
