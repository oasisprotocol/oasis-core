su -s /bin/sh -c '
AESM_PATH=/opt/intel/libsgx-enclave-common/aesm
cd "$AESM_PATH"
export AESM_PATH
export LD_LIBRARY_PATH="$AESM_PATH"
exec ./aesm_service --no-daemon
' aesmd &
