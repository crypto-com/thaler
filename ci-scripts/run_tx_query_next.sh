#!/bin/bash
set -ex

echo "[Config] SGX_MODE=${SGX_MODE}"
echo "[Config] TX_QUERY_TIMEOUT=${TX_QUERY_TIMEOUT}"

mkdir -p /var/run/aesmd/
NAME=aesm_service AESM_PATH=/opt/intel/sgx-aesm-service/aesm LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm /opt/intel/sgx-aesm-service/aesm/aesm_service &
echo "[aesm_service] Running in background ..."
# Wait for aesm_service to initialize
sleep 20

# assumes SPID + IAS_API_KEY are set
PID=$!
trap 'kill -TERM $PID' TERM INT EXIT
./ra-sp-server --quote-type Unlinkable --ias-key $IAS_API_KEY --spid $SPID &
echo "[ra-sp-server] Running in background ..."
PID=$!
trap 'kill -TERM $PID' TERM INT EXIT
# Wait for ra-sp-server to initialize
sleep 2
RUST_LOG=${RUST_LOG} ./tx-query2-app-runner --enclave-path tx-query2-enclave-app.sgxs --address 0.0.0.0:${APP_PORT_QUERY} --zmq-conn-str ${TX_VALIDATION_CONN} --sp-address 0.0.0.0:8989
