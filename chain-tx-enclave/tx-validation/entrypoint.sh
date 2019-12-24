#!/bin/bash
set -e

source /root/.docker_bashrc

echo "[Config] SGX_MODE=${SGX_MODE}"
echo "[Config] NETWORK_ID=${NETWORK_ID}"

if [ x"${SGX_MODE}" == "xHW" ]; then
  LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service &

  echo "[aesm_service] Running in background ..."
  # Wait for aesm_service to initialize
  sleep 1
fi

trap 'kill -TERM $PID' TERM INT
tx-validation-app tcp://0.0.0.0:${APP_PORT} &
PID=$!
echo "[tx-validation-app] Running in background ..."
wait $PID
wait $PID
exit $?
