#!/bin/sh -eu

usage() {
  echo >&2 "usage: $0 --node-address <node_address> --runtime-id <unused> -- <txsource args ...>"
  #                0  1              2              3            4        5
  exit 1
}

if [ "$1" = "--node-address" ]; then
  node_address=$2
else
  usage
fi
if [ "$5" = "--" ]; then
  shift 5
else
  usage
fi

exec ./go/oasis-node/oasis-node debug txsource \
  --address "$node_address" \
  "$@"
