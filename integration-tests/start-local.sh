#!/usr/bin/env bash
set -e
IFS=

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
# @argument Docker name
function start_chain_tx_enclave() {
    print_config "CHAIN_TX_ENCLAVE_DIRECTORY" "${CHAIN_TX_ENCLAVE_DIRECTORY}"
    print_config "CHAIN_HEX_ID" "${CHAIN_HEX_ID}"
    print_config "PORT" "${1}"

    print_step "Trying to kill previous docker instance ${4}"
    set +e
    docker kill "${2}"
    set -e
    
    docker run --rm \
        -p "${1}:25933" \
        --name "${2}" \
        --env RUST_BACKTRACE=1 \
        --env RUST_LOG=debug \
        "${CHAIN_TX_ENCLAVE_DOCKER_IMAGE}"
}

# @argument Tendermint folder path
# @argument Tendermint Port
# @argument chain-abci Port
# @argument Docker name
function start_tendermint() {
    print_config "CHAIN_ID" "${CHAIN_ID}"
    print_config "TENDERMINT_FOLDER_PATH" "${1}"
    print_config "TENDERMINT_PORT" "${2}"
    print_config "CHAIN_ABCI_PORT" "${3}"

    TENDERMINT_GENESIS_APP_HASH="$(cat "${1}/config/genesis.json" | jq -r .app_hash)"
    print_config "TENDERMINT_GENESIS_APP_HASH" "${TENDERMINT_GENESIS_APP_HASH}"

    print_step "Trying to kill previous docker instance ${4}"
    set +e
    docker kill "${4}"
    set -e

    STORAGE="/tmp$(mktemp -d)"
    mkdir -p "${STORAGE}"
    cp -r "${1}/." "${STORAGE}"
    print_config "STORAGE" "${STORAGE}"

    docker run --rm \
        -v "${STORAGE}:/tendermint" \
        -p "${2}:26657" \
        --name "${4}" \
        --env TMHOME=/tendermint \
        "tendermint/tendermint:v${TENDERMINT_VERSION}" \
        node \
            --proxy_app="tcp://host.docker.internal:${3}" \
            --rpc.laddr=tcp://0.0.0.0:26657 \
            --consensus.create_empty_blocks=true
}

# @argument App Hash
# @argument Chain ABCI Port
# @argument Enclave Port
function start_chain_abci() {
    print_config "CHAIN_ID" "${CHAIN_ID}"
    print_config "GENESIS_APP_HASH" "${1}"
    print_config "PORT" "${2}"
    print_config "ENCLAVE_PORT" "${3}"

    STORAGE=$(mktemp -d)    
    print_config "STORAGE" "${STORAGE}"

    export RUST_BACKTRACE=1
    export RUST_LOG=info
    cargo run \
        --bin chain-abci -- \
            --data "${STORAGE}" \
            --port "${2}" \
            --chain_id "${CHAIN_ID}" \
            --genesis_app_hash ${1} \
            --enclave_server "tcp://127.0.0.1:${3}"
}

# @argument Wallet Storage directory
# @argument ClientRPC Port
# @argument Tendermint Port
function start_client_rpc() {
    print_config "CHAIN_ID" "${CHAIN_ID}"
    print_config "WALLET_STORAGE_DIRECTORY" "${WALLET_STORAGE_DIRECTORY}"
    print_config "PORT" "${1}"
    print_config "TENDERMINT_PORT" "${2}"

    STORAGE=$(mktemp -d)    
    cp -r "${WALLET_STORAGE_DIRECTORY}/." "${STORAGE}"
    print_config "STORAGE" "${STORAGE}"

    RUST_BACKTRACE=1 && RUST_LOG=info cargo run \
        --bin client-rpc -- \
            --port "${1}" \
            --chain-id "${CHAIN_ID}" \
            --storage-dir "${STORAGE}" \
            --websocket-url "ws://127.0.0.1:${2}/websocket"
}

# @argument Wallet Storage directory
# @argument Tendermint Port
function start_client_cli() {
    print_config "CHAIN_ID" "${CHAIN_ID}"
    print_config "WALLET_STORAGE_DIRECTORY" "${WALLET_STORAGE_DIRECTORY}"
    print_config "TENDERMINT_PORT" "${1}"

    STAKING_ADDRESS=$(cat ./address-state.json | jq -r '.staking')
    TRANSFER_ADDRESSES=$(cat ./address-state.json | jq -r '.transfer')
    print_config "STAKING_ADDRESS" "${STAKING_ADDRESS}"
    print_config "TRANSFER_ADDRESSES" "${TRANSFER_ADDRESSES}"

    STORAGE=$(mktemp -d)    
    cp -r "${WALLET_STORAGE_DIRECTORY}/." "${STORAGE}"
    print_config "STORAGE" "${STORAGE}"

    echo
    echo "CRYPTO_CHAIN_ID="${CHAIN_ID}" \\"
    echo "CRYPTO_CLIENT_STORAGE="${STORAGE}" \\"
    echo "CRYPTO_CLIENT_TENDERMINT="ws://127.0.0.1:${1}/websocket" \\"
    echo "RUST_BACKTRACE=1 \\"
    echo "RUST_LOG=info \\"
    echo "    cargo run --bin client-cli --"
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
    start_chain_tx_enclave 15933 "chain-tx-enclave-zerofee"
elif [ x"${1}" == "xchain-tx-enclave" ]; then
    start_chain_tx_enclave 25933 "chain-tx-enclave"
elif [ x"${1}" == "xtendermint-zerofee" ]; then
    start_tendermint "${TENDERMINT_ZEROFEE_DIRECTORY}" 16657 16658 "tendermint-zerofee"
elif [ x"${1}" == "xtendermint" ]; then
    start_tendermint "${TENDERMINT_WITHFEE_DIRECTORY}" 26657 26658 "tendermint"
elif [ x"${1}" == "xchain-abci-zerofee" ]; then
    start_chain_abci "${ZEROFEE_APP_HASH}" 16658 15933
elif [ x"${1}" == "xchain-abci" ]; then
    start_chain_abci "${WITHFEE_APP_HASH}" 26658 25933
elif [ x"${1}" == "xclient-rpc-zerofee" ]; then
    start_client_rpc 16659 16657
elif [ x"${1}" == "xclient-rpc" ]; then
    start_client_rpc 26659 26657
elif [ x"${1}" == "xclient-cli-zerofee" ]; then
    start_client_cli 16657
elif [ x"${1}" == "xclient-cli" ]; then
    start_client_cli 26657
else
    print_error "Unknown command ${1}"
fi
