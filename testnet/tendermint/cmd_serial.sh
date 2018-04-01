#!/bin/sh -eux
ssh -F ./ssh_config val1 "$@"
ssh -F ./ssh_config val2 "$@"
ssh -F ./ssh_config val3 "$@"
