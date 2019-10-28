#!/usr/bin/env bash
set -e
IFS=

export WALLET_PASSPHRASE=${WALLET_PASSPHRASE:-123456}
export TENDERMINT_VERSION=${TENDERMINT_VERSION:-0.32.0}

# Constants (No not modify unless you are absolutely sure what you are doing)
export CHAIN_DOCKER_IMAGE="integration-tests-chain"
export CHAIN_TX_ENCLAVE_DOCKER_IMAGE="integration-tests-chain-tx-enclave"
export TENDERMINT_TEMP_DIRECTORY="docker-data/temp/tendermint"
export TENDERMINT_WITHFEE_DIRECTORY="docker-data/withfee/tendermint"
export TENDERMINT_ZEROFEE_DIRECTORY="docker-data/zerofee/tendermint"
export CHAIN_ABCI_WITHFEE_DIRECTORY="docker-data/withfee/chain-abci"
export CHAIN_ABCI_ZEROFEE_DIRECTORY="docker-data/zerofee/chain-abci"
export ENCLAVE_WITHFEE_DIRECTORY="docker-data/withfee/chain-tx-enclave"
export ENCLAVE_ZEROFEE_DIRECTORY="docker-data/zerofee/chain-tx-enclave"
export WALLET_STORAGE_TEMP_DIRECTORY="docker-data/temp/wallet-storage"
export WALLET_STORAGE_WITHFEE_DIRECTORY="docker-data/withfee/wallet-storage"
export WALLET_STORAGE_ZEROFEE_DIRECTORY="docker-data/zerofee/wallet-storage"
export DEVCONF_WITHFEE_PATH="docker-data/temp/dev_conf_withfee.json"
export DEVCONF_ZEROFEE_PATH="docker-data/temp/dev_conf_zerofee.json"
export ADDRESS_STATE_PATH="address-state.json"

export CHAIN_ID="test-chain-y3m1e6-AB"
export CHAIN_HEX_ID="AB"

set +e
