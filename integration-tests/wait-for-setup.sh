#!/usr/bin/env bash
set -e
IFS=

# Maximum number of trial
MAX_TRIALS=${MAX_TRIALS:-12}
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

# Test Tendermint is up
# @argument Tendermint port
function is_tendermint_up() {
    echo "Checking Tendermint status (${1}) ..."
    curl -sSf -X POST "127.0.0.1:${1}" \
        -H 'Content-Type: application/json' \
        -d '{
            "method": "block",
            "jsonrpc": "2.0",
            "params": [1],
            "id": "block"
        }' > /dev/null
    RET_VALUE=$?
}

# Test ClientRPC is up
# @argument ClientRPC port
function is_client_rpc_up() {
    echo "Checking ClientRpc status (${1}) ..."
    curl -sSf -X POST "127.0.0.1:${1}" \
        -H 'Content-Type:application/json' \
        -d '{
            "method":"wallet_list",
            "jsonrpc":"2.0",
            "params":[],
            "id":"wallet_list"
        }' > /dev/null
    RET_VALUE=$?
}

check_command_exist "curl"

trial=1
MAX_TRIALS_LIMIT=$(( $MAX_TRIALS + 1 ))
while true; do
    print_step "Waiting for Tendermint and ClientRPC readiness ... (${trial})"
    is_tendermint_up "${TENDERMINT_RPC_PORT:-26657}" && WITHFEE_TENDERMINT_READY=${RET_VALUE}
    is_tendermint_up "${TENDERMINT_ZEROFEE_RPC_PORT:-16657}" && ZEROFEE_TENDERMINT_READY=${RET_VALUE}
    is_client_rpc_up "${CLIENT_RPC_PORT:-26659}" && WITHFEE_CLIENT_RPC_READY=${RET_VALUE}
    is_client_rpc_up "${CLIENT_RPC_ZEROFEE_PORT:-16659}" && ZEROFEE_CLIENT_RPC_READY=${RET_VALUE}
    if [ "${WITHFEE_TENDERMINT_READY}" == "0" ] && [ "${ZEROFEE_TENDERMINT_READY}" == "0" ] && [ "${WITHFEE_CLIENT_RPC_READY}" == "0" ] && [ "${ZEROFEE_CLIENT_RPC_READY}" == "0" ]; then
        print_step "All Tendermint and ClientRPC are ready"
        break
    fi

    trial=$(( $trial + 1 ))
    if [ "${trial}" == "${MAX_TRIALS_LIMIT}" ]; then
        print_step "Exceeded number of trials (${MAX_TRIALS}) but Tendermint and ClientRPC are still not ready, exiting ..."
        exit 1
    fi

    sleep 5
done

exit 0
