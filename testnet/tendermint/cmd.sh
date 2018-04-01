#!/bin/sh -eu
ssh -F ./ssh_config val1 "$@" &
ssh -F ./ssh_config val2 "$@" &
ssh -F ./ssh_config val3 "$@" &
wait
