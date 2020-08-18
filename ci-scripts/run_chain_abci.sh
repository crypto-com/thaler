#!/bin/bash
set -e

if [[ ! -z "$TX_QUERY_HOSTNAME" ]]; then
  PREFIX=""
fi
TX_QUERY_HOSTNAME=${TX_QUERY_HOSTNAME:-"chain-abci"}

echo "[Config] SGX_MODE=${SGX_MODE}"
echo "[Config] NETWORK_ID=${NETWORK_ID}"
echo "[Config] TX_QUERY_HOSTNAME=${TX_QUERY_HOSTNAME}"

if [ x"${SGX_MODE}" == "xHW" ]; then
  mkdir -p /var/run/aesmd/
  NAME=aesm_service AESM_PATH=/opt/intel/sgx-aesm-service/aesm LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm /opt/intel/sgx-aesm-service/aesm/aesm_service &

  echo "[aesm_service] Running in background ..."
  # Wait for aesm_service to initialize
  sleep 15
fi

PID=$!
trap 'kill -TERM $PID' TERM INT EXIT

./ra-sp-server --quote-type Unlinkable --ias-key $IAS_KEY --spid $SPID &
echo "[ra-sp-server] Running in background ..."
PID=$!
trap 'kill -TERM $PID' TERM INT EXIT

sleep 5

echo "[Config] init chain abci config on port 26658 and set config"
chain-abci init \
    --data /crypto-chain/chain-storage 

sed -i -e '/launch_ra_proxy:/ s/: .*/: false/' /crypto-chain/chain-storage/config.yaml  
sed -i -e '/tx_query_listen:/ s/: .*/: 0.0.0.0:26651/' /crypto-chain/chain-storage/config.yaml
sed -i -e "/tx_query:/ s/: .*/: ${PREFIX}${TX_QUERY_HOSTNAME}:26651/" /crypto-chain/chain-storage/config.yaml
sed -i -e '/host:/ s/: .*/: 0.0.0.0/' /crypto-chain/chain-storage/config.yaml
sed -i -e '/port:/ s/: .*/: 26658/' /crypto-chain/chain-storage/config.yaml

echo "[Config] start chain abci"
chain-abci run \
    --chain_id ${CHAIN_ID} \
    --data /crypto-chain/chain-storage \
    --genesis_app_hash ${APP_HASH}
