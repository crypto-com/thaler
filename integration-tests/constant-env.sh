#!/usr/bin/env bash
set -e
IFS=

TENDERMINT_PATH=${TENDERMINT_PATH:-tendermint}
WALLET_PASSPHRASE=${WALLET_PASSPHRASE:-123456}
TENDERMINT_VERSION=${TENDERMINT_VERSION:-0.32.0}

# Constants (No not modify unless you are absolutely sure what you are doing)
CHAIN_TX_ENCLAVE_DIRECTORY="docker/chain-tx-enclave"
CHAIN_TX_ENCLAVE_DOCKER_IMAGE="local-integration-tests-chain-tx-enclave"
WALLET_STORAGE_DIRECTORY="docker/chain/wallet-storage"
ADDRESS_STATE_PATH="address-state.json"
DEV_CONF_WITHFEE_PATH="dev-conf-withfee.json"
DEV_CONF_ZEROFEE_PATH="dev-conf-zerofee.json"
TENDERMINT_TEMP_DIRECTORY="tendermint"
TENDERMINT_WITHFEE_DIRECTORY="docker/tendermint/tendermint-withfee"
TENDERMINT_ZEROFEE_DIRECTORY="docker/tendermint/tendermint-zerofee"
CHAIN_ID="test-chain-y3m1e6-AB"
CHAIN_HEX_ID="AB"

set +e
