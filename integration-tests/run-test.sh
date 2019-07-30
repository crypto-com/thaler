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

check_command_exist "jq"

# Test Tendermint
# @argument Tendermint port
# @argument Expected App Hash
function test_tendermint() {
    GENESIS=$(curl -sSf -X POST "127.0.0.1:${1}" \
        -H 'Content-Type: application/json' \
        -d '{
            "method": "genesis",
            "jsonrpc": "2.0",
            "params": [],
            "id": "genesis"
        }'
    )
    GENESIS_CHAIN_ID=$(echo "${GENESIS}" | jq -r .result.genesis.chain_id)
    GENESIS_APP_HASH=$(echo "${GENESIS}" | jq -r .result.genesis.app_hash)
    if [ x"${GENESIS_CHAIN_ID}" != x"${CHAIN_ID}" ]; then
        print_error "Mismatched CHAIN_ID from 127.0.0.1:${1}, expected: ${CHAIN_ID}, found: ${GENESIS_CHAIN_ID}"
        exit 1;
    fi
    if [ x"${GENESIS_APP_HASH}" != x"${2}" ]; then
        print_error "Mismatched APP_HASH from 127.0.0.1:${1}, expected: ${2}, found: ${GENESIS_APP_HASH}"
        exit 1;
    fi
}

# Test ClientRPC has Default wallet
# @argument ClientRPC port
function test_client_rpc() {
    WALLET_LIST=$(curl -sSf -X POST "127.0.0.1:${1}" \
        -H 'Content-Type:application/json' \
        -d '{
            "method":"wallet_list",
            "jsonrpc":"2.0",
            "params":[],
            "id":"wallet_list"
        }'
    )
    FIRST_WALLET=$(echo "${WALLET_LIST}" | jq -r .result[0])
    if [ x"${FIRST_WALLET}" != "xDefault" ]; then
        print_error "Missing Default wallet from ClientRPC 127.0.0.1:${1}"
        exit 1;
    fi
}

print_step "Testing Tendermint"
test_tendermint 26657 "${WITHFEE_APP_HASH}"
test_tendermint 16657 "${ZEROFEE_APP_HASH}"

print_step "Testing ClientRPC"
test_client_rpc 26659
test_client_rpc 16659
