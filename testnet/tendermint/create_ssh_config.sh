#!/bin/sh -eu

{
  read val1
  read val2
  read val3
} <ips.txt

cat <<EOF >ssh_config
User ec2-user
UserKnownHostsFile ./known_hosts
ControlMaster auto
ControlPath ./control/%h

Host val1
HostName $val1
IdentityFile ./keys/ekidentm-us-west-1.pem

Host val2
HostName $val2
IdentityFile ./keys/ekidentm-us-west-1.pem

Host val3
HostName $val3
IdentityFile ./keys/ekidentm-us-west-1.pem
EOF
