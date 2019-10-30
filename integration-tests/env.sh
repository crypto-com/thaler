#!/usr/bin/env bash
set -e
IFS=

. ./const-env.sh

TENDERMINT_WITHFEE_GENESIS_PATH="${TENDERMINT_WITHFEE_DIRECTORY}/config/genesis.json"
TENDERMINT_ZEROFEE_GENESIS_PATH="${TENDERMINT_ZEROFEE_DIRECTORY}/config/genesis.json"

# Global function return value
RET_VALUE=0

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

# Awlays execute at script located directory
CWD=$(pwd)
if [ x"$(basename "${0}")" = "xenv.sh" ]; then
    cd "$(dirname "${0}")"
fi
# Travis CI run `. ./env.sh` using `build.sh`. i.e. `${0}`` is `/home/travis/build.sh`

check_command_exist "jq"

export CHAIN_ID=$(cat "${TENDERMINT_WITHFEE_GENESIS_PATH}" | jq -r .chain_id)
export CHAIN_HEX_ID="${CHAIN_ID: -2}"
export WITHFEE_APP_HASH=$(cat "${TENDERMINT_WITHFEE_GENESIS_PATH}" | jq -r .app_hash)
export ZEROFEE_APP_HASH=$(cat "${TENDERMINT_ZEROFEE_GENESIS_PATH}" | jq -r .app_hash)

cd "${CWD}"
set +e
