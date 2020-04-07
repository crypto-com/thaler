#!/bin/bash
set -e

echo "[Config] SGX_MODE=${SGX_MODE}"
echo "[Config] TX_QUERY_TIMEOUT=${TX_QUERY_TIMEOUT}"

mkdir -p /var/run/aesmd/
NAME=aesm_service AESM_PATH=/opt/intel/sgx-aesm-service/aesm LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm /opt/intel/sgx-aesm-service/aesm/aesm_service &
echo "[aesm_service] Running in background ..."
# Wait for aesm_service to initialize
sleep 4

# assumes SPID + IAS_API_KEY are set
PID=$!
trap 'kill -TERM $PID' TERM INT
RUST_LOG=${RUST_LOG} ./tx-query-app 0.0.0.0:${APP_PORT_QUERY} ${TX_VALIDATION_CONN} ${TX_QUERY_TIMEOUT}
