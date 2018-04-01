#!/bin/sh -eu
scp -F ./ssh_config "$@" val1:~ &
scp -F ./ssh_config "$@" val2:~ &
scp -F ./ssh_config "$@" val3:~ &
wait
