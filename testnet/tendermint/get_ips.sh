#!/bin/bash -eu
set -o pipefail
get_ip() {
  region=$1
  inst=$2
  aws ec2 describe-instances --region "$region" --instance-ids "$inst" | jq -r '.Reservations[0].Instances[].PublicIpAddress'
}

get_ip us-west-1 i-027047714e3581ec6
get_ip us-west-1 i-0ba558494bad22313
get_ip us-west-1 i-0cc82c78707f12e05
