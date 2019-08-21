#!/usr/bin/env bash
set -e
IFS=

WALLET_WITHFEE_STORAGE_DIRECTORY="wallet-storage-withfee"
WALLET_ZEROFEE_STORAGE_DIRECTORY="wallet-storage-zerofee"

# Global function return value
RET_VALUE=0

# @argument message
function print_message() {
    echo "[$(date +"%Y-%m-%d|%T")] ${1}"
}

# @argument Description
function print_step() {
    print_message "${1}"
}

# @argument Key
# @argument Value
function print_config() {
    print_message "[Config] ${1}=${2}"
}

# @argument Description
function print_error() {
    print_message "[ERROR] ${1}"
}

# @argument Command to test
function check_command_exist() {
    set +e
    command -v ${1} > /dev/null
    if [ x"$?" = "x1" ]; then
        print_error "command not found: ${1}"
        exit 1
    fi
    set -e
}

# @argument Port
function start_chain_tx_enclave() {
    print_config "CHAIN_TX_ENCLAVE_DIRECTORY" "${CHAIN_TX_ENCLAVE_DIRECTORY}"
    print_config "CHAIN_HEX_ID" "${CHAIN_HEX_ID}"
    print_config "PORT" "${1}"

    cd "${CHAIN_TX_ENCLAVE_DIRECTORY}" && docker build -t chain-tx-validation \
        -f ./tx-validation/Dockerfile . \
        --build-arg SGX_MODE=SW \
        --build-arg NETWORK_ID="${CHAIN_HEX_ID}"
    
    docker run --rm \
        -p "${1}:25933" \
        chain-tx-validation
}

# @argument Tendermint folder path
# @argument Tendermint Port
# @argument chain-abci Port
function start_tendermint() {
    print_config "CHAIN_ID" "${CHAIN_ID}"
    print_config "TENDERMINT_FOLDER_PATH" "${1}"
    print_config "TENDERMINT_PORT" "${2}"
    print_config "CHAIN_ABCI_PORT" "${3}"

    docker run -v "$(pwd)/${1}:/tendermint" \
        --env TMHOME=/tendermint \
        -p "${2}:26657" \
        "tendermint/tendermint:v${TENDERMINT_VERSION}" \
        node \
            --proxy_app="tcp://host.docker.internal:${3}" \
            --rpc.laddr=tcp://0.0.0.0:26657 \
            --consensus.create_empty_blocks=false
}

# @argument App Hash
# @argument Chain ABCI Port
# @argument Enclave Port
function start_chain_abci() {
    print_config "CHAIN_ID" "${CHAIN_ID}"
    print_config "GENESIS_APP_HASH" "${1}"
    print_config "PORT" "${2}"
    print_config "ENCLAVE_PORT" "${3}"

    RUST_BACKTRACE=1 && RUST_LOG=info cargo run \
        --bin chain-abci -- \
            --port "${1}" \
            --chain_id "${CHAIN_ID}" \
            --genesis_app_hash ${1} \
            --enclave_server "tcp://127.0.0.1:${3}"
}

# @argument Wallet Storage directory
# @argument ClientRPC Port
# @argument Tendermint Port
function start_client_rpc() {
    print_config "CHAIN_HEX_ID" "${CHAIN_HEX_ID}"
    print_config "WALLET_STORAGE_DIRECTORY" "${WALLET_STORAGE_DIRECTORY}"
    print_config "PORT" "${1}"
    print_config "TENDERMINT_PORT" "${2}"

    rm -rf "/tmp/${2}"
    mkdir -p  "/tmp/${2}"
    cp -r "${WALLET_STORAGE_DIRECTORY}" "/tmp/${2}"

    RUST_BACKTRACE=1 && RUST_LOG=info cargo run \
        --bin client-rpc -- \
            --port "${2}" \
            --network_id "${CHAIN_HEX_ID}" \
            --storage-dir "${1}" \
            --tendermint-url "http://127.0.0.1:${3}"
}

# Always execute at script located directory
cd "$(dirname "${0}")"

# Source constants
. ./constant-env.sh
. ./env.sh

check_command_exist "tendermint"
check_command_exist "cargo"
check_command_exist "docker"

if [ x"${1}" == "xchain-tx-enclave-zerofee" ]; then
    start_chain_tx_enclave 15933
elif [ x"${1}" == "xchain-tx-enclave" ]; then
    start_chain_tx_enclave 25933
elif [ x"${1}" == "xtendermint-zerofee" ]; then
    start_tendermint "${TENDERMINT_ZEROFEE_DIRECTORY}" 16657 16658
elif [ x"${1}" == "xtendermint" ]; then
    start_tendermint "${TENDERMINT_WITHFEE_DIRECTORY}" 26657 26658
elif [ x"${1}" == "xchain-abci-zerofee" ]; then
    start_chain_abci "${ZEROFEE_APP_HASH}" 16658 15933
elif [ x"${1}" == "xchain-abci" ]; then
    start_chain_abci "${WITHFEE_APP_HASH}" 26658 25933
elif [ x"${1}" == "xclient-rpc-zerofee" ]; then
    start_client_rpc "${WALLET_WITHFEE_STORAGE_DIRECTORY}" 16659 26657
elif [ x"${1}" == "xclient-rpc" ]; then
    start_client_rpc "${WALLET_ZEROFEE_STORAGE_DIRECTORY}" 26659 26657
fi
