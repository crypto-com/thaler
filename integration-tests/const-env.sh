#!/usr/bin/env bash
set -e
IFS=

export WALLET_PASSPHRASE=${WALLET_PASSPHRASE:-123456}
export TENDERMINT_VERSION=${TENDERMINT_VERSION:-0.32.8}
export SGX_MODE=${SGX_MODE:-SW}
export DOCKER_SGX_DEVICE_BINDING="/dev/zero:/dev/dummy"
if [ ! -z "${DRONE}" ]; then
    export SGX_MODE=HW
    export DOCKER_SGX_DEVICE_BINDING="${SGX_DEVICE:-"/dev/sgx"}:/dev/sgx"
fi

# Constants (No not modify unless you are absolutely sure what you are doing)
export CHAIN_DOCKER_IMAGE="integration-tests-chain"
export CHAIN_TX_ENCLAVE_DOCKER_IMAGE="integration-tests-chain-tx-enclave"
export CHAIN_TX_ENCLAVE_QUERY_DOCKER_IMAGE="integration-tests-chain-tx-enclave-query"
export DOCKER_DATA_DIRECTORY="docker-data"
export TENDERMINT_TEMP_DIRECTORY="${DOCKER_DATA_DIRECTORY}/temp/tendermint"
export TENDERMINT_WITHFEE_DIRECTORY="${DOCKER_DATA_DIRECTORY}/withfee/tendermint"
export TENDERMINT_ZEROFEE_DIRECTORY="${DOCKER_DATA_DIRECTORY}/zerofee/tendermint"
export CHAIN_ABCI_WITHFEE_DIRECTORY="${DOCKER_DATA_DIRECTORY}/withfee/chain-abci"
export CHAIN_ABCI_ZEROFEE_DIRECTORY="${DOCKER_DATA_DIRECTORY}/zerofee/chain-abci"
export ENCLAVE_WITHFEE_DIRECTORY="${DOCKER_DATA_DIRECTORY}/withfee/chain-tx-enclave"
export ENCLAVE_ZEROFEE_DIRECTORY="${DOCKER_DATA_DIRECTORY}/zerofee/chain-tx-enclave"
export WALLET_STORAGE_TEMP_DIRECTORY="${DOCKER_DATA_DIRECTORY}/temp/wallet-storage"
export WALLET_STORAGE_WITHFEE_DIRECTORY="${DOCKER_DATA_DIRECTORY}/withfee/wallet-storage"
export WALLET_STORAGE_ZEROFEE_DIRECTORY="${DOCKER_DATA_DIRECTORY}/zerofee/wallet-storage"
export DEVCONF_WITHFEE_PATH="${DOCKER_DATA_DIRECTORY}/temp/dev_conf_withfee.json"
export DEVCONF_ZEROFEE_PATH="${DOCKER_DATA_DIRECTORY}/temp/dev_conf_zerofee.json"
export ADDRESS_STATE_PATH="address-state.json"

export CHAIN_ID="test-chain-y3m1e6-AB"
export CHAIN_HEX_ID="AB"

set +e
