#!/bin/sh -eu

{
  read val1
  read val2
  read val3
} <ips.txt

cat <<EOF >known_hosts
$val1 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIz9F2mciwJvwBHapxc0OJELhq0J7qWtrE0diBev2W/DCRjj/sIfJSYQBtaIsO7cxg3YAjekR8rMtuhfB9bzBFU=
$val2 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE/4R+LZYgv/HWw7GPUDbKU3WYEDJge+FhepmPdT064sAwLdU0EE7k8F7Lzw9VWIis7lz8aB6A9Zmv6tdkAPugo=
$val3 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNGNXATGDPnQBp4hMpeZuLGuog0+SeDmj7kk6skSu4sLrb7j6Y14eDiPeKmgIsOAfQks6lIps3vHS6ZTjlpfMP0=
EOF
