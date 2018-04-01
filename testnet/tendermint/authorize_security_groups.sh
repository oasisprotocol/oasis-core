#!/bin/sh -eu

{
  read val1
  read val2
  read val3
} <ips.txt

ranges='[{"CidrIp":"'"$val1"'/32"},{"CidrIp":"'"$val2"'/32"},{"CidrIp":"'"$val3"'/32"}]'
set -x
region=us-west-1
aws --region "$region" ec2 authorize-security-group-ingress --group-name tendermint --ip-permissions '[{"IpProtocol":"-1","IpRanges":'"$ranges"'}]'
