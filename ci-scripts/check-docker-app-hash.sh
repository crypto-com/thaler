#!/usr/bin/env bash

set -e

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

GENERATED_APP_HASH=$(./target/debug/dev-utils genesis generate --genesis_dev_config_path ./docker/config/devnet/dev-conf.json --tendermint_genesis_path ./docker/config/devnet/tendermint/genesis.json | jq -r '.app_hash')
GENESIS_APP_HASH=$(cat ./docker/config/devnet/tendermint/genesis.json | jq -r '.app_hash')

if [ x"${GENERATED_APP_HASH}" != x"${GENESIS_APP_HASH}" ]; then
    echo "Devnet genesis app_hash in docker is inconsistent with generated app_hash"
    exit 1
fi
