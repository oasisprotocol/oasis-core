#!/bin/sh -eu

{
  read val1
  read val2
  read val3
} <ips.txt
port=46656
seeds="$val1:$port,$val2:$port,$val3:$port"

for n in val1 val2 val3; do
  ssh -F ./ssh_config "$n" ./ekiden-consensus &
  ssh -F ./ssh_config "$n" ./tendermint node \
      --p2p.seeds="$seeds" \
      --moniker="$n" \
      --consensus.create_empty_blocks=false \
      --rpc.laddr tcp://0.0.0.0:46666 \
      --rpc.grpc_laddr tcp://0.0.0.0:46657 &
done
wait
