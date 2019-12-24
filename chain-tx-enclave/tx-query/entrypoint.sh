#!/bin/bash
set -e

source /root/.docker_bashrc

echo "[Config] SGX_MODE=${SGX_MODE}"
echo "[Config] TX_QUERY_TIMEOUT=${TX_QUERY_TIMEOUT}"

LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service &

echo "[aesm_service] Running in background ..."
# Wait for aesm_service to initialize
sleep 1

# assumes SPID + IAS_API_KEY are set

trap 'kill -TERM $PID' TERM INT
tx-query-app 0.0.0.0:${APP_PORT} ${TX_VALIDATION_CONN} ${TX_QUERY_TIMEOUT} &
PID=$!
echo "[tx-validation-app] Running in background ..."
wait $PID
wait $PID
exit $?
