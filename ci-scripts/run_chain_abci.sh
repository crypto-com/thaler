#!/bin/bash
set -e

echo "[Config] SGX_MODE=${SGX_MODE}"
echo "[Config] NETWORK_ID=${NETWORK_ID}"

if [ x"${SGX_MODE}" == "xHW" ]; then
  LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service &

  echo "[aesm_service] Running in background ..."
fi

PID=$!
trap 'kill -TERM $PID' TERM INT

echo "[Config] start chain abci on port 26658"
chain-abci \
    --chain_id ${CHAIN_ID} \
    --data /crypto-chain/chain-storage \
    --enclave_server ${TX_VALIDATION_CONN} \
    --genesis_app_hash ${APP_HASH} \
    --host 0.0.0.0 \
    --port 26658 \
    --tx_query ${PREFIX}sgx-query:26651