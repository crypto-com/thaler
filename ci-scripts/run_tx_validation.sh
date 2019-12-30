#!/bin/bash
set -e

echo "[Config] SGX_MODE=${SGX_MODE}"
echo "[Config] NETWORK_ID=${NETWORK_ID}"

if [ x"${SGX_MODE}" == "xHW" ]; then
  LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service &

  echo "[aesm_service] Running in background ..."
  # Wait for aesm_service to initialize
  sleep 4
fi

trap 'kill -TERM $PID' TERM INT
echo "[Config] start enclave on port ${APP_PORT_VALIDATION}"
RUST_LOG=${RUST_LOG} ./tx-validation-app tcp://0.0.0.0:${APP_PORT_VALIDATION}
