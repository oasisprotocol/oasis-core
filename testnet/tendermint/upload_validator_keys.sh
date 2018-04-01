#!/bin/sh -eu
for n in val1 val2 val3; do
  scp -F ./ssh_config genesis.json "validators/$n/priv_validator.json" "$n:~/.tendermint" &
done
wait
