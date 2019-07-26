#!/usr/bin/env bash
set -e
IFS=

TENDERMINT_PATH=${TENDERMINT_PATH:-tendermint}
WALLET_PASSPHRASE=${WALLET_PASSPHRASE:-123456}

# @argument Description
function print_step() {
    echo "[$(date +"%Y-%m-%d|%T")] ${1}"
}

# @argument Description
function print_error() {
    echo "[$(date +"%Y-%m-%d|%T")][ERROR] ${1}"
}

# @argument Command to test
function check_command_exist() {
    set +e
    command -v ${1}
    if [ x"$?" = "x1" ]; then
        print_error "command not found: ${1}"
        exit 1
    fi
    set -e
}

# Create wallet
# @argument Wallet Name
# @argument Wallet Passphrase
function create_wallet() {
    print_step "Creating wallet \"${1}\""
    printf "${2}\n" | ../target/debug/client-cli wallet new --name ${1}
}

# Create wallet staking address
# @argument Wallet Name
# @argument Wallet Passphrase
function create_wallet_staking_address() {
    print_step "Creating address for wallet \"${1}\""
    printf "${2}\n" | ../target/debug/client-cli address new --name ${1} --type Staking

    print_step "Retrieving last address for wallet \"${1}\""
    ADDRESS_LIST=$(printf "${2}\n" | ../target/debug/client-cli address list --name ${1} --type Staking)
    echo $ADDRESS_LIST
    echo $ADDRESS_LIST | tail -n2 | awk -F "Address: " '{print $2}' | head -n1 | tr -d '\n'
}

# @argument Staking Address
# @argument Base Fee
# @argument Per Byte Fee
# @argument Validator Pub Key
# @argument Genesis Time
# @argument Ouput File Path
function substitute_dev_conf() {
    print_step "Substituting dev-utils configuration ${6}"
	echo "${DEV_CONF}" | \
		sed "s/{STAKING_ADDRESS}/${1}/g" | \
		sed "s/{BASE_FEE}/${2}/g" | \
		sed "s/{PER_BYTE_FEE}/${3}/g" | \
        sed "s/{PUB_KEY}/${4}/g" | \
		sed "s/{GENESIS_TIME}/${5}/g" > ${6}
}
DEV_CONF=$(cat << EOF
{
    "distribution": {
        "{STAKING_ADDRESS}": "2500000000000000000",
        "0x20a0bee429d6907e556205ef9d48ab6fe6a55531": "2500000000000000000",
        "0x35f517cab9a37bc31091c2f155d965af84e0bc85": "2500000000000000000",
        "0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de": "1250000000000000000",
        "0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07": "1250000000000000000"
    },
    "unbonding_period": 60,
    "required_council_node_stake": "1250000000000000000",
    "initial_fee_policy": {
        "base_fee": "{BASE_FEE}",
        "per_byte_fee": "{PER_BYTE_FEE}"
    },
    "council_nodes": [
        {
            "staking_account_address": "0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de",
            "consensus_pubkey_type": "Ed25519",
            "consensus_pubkey_b64": "{PUB_KEY}"
        }
    ],
    "launch_incentive_from": "0x35f517cab9a37bc31091c2f155d965af84e0bc85",
    "launch_incentive_to": "0x20a0bee429d6907e556205ef9d48ab6fe6a55531",
    "long_term_incentive": "0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07",
    "genesis_time": "{GENESIS_TIME}"
}
EOF
)

# Change working directory
cd "$(dirname "${0}")"

check_command_exist "jq"

print_step "Tendermint init"
eval ${TENDERMINT_PATH} init

create_wallet "Default" "${WALLET_PASSPHRASE}"

STAKING_ADDRESS=$(create_wallet_staking_address "Default" ${WALLET_PASSPHRASE})
GENESIS_TIME=$(cat ~/.tendermint/config/genesis.json | jq -r .genesis_time)
VALIDATOR_PUB_KEY=$(cat ~/.tendermint/config/genesis.json | jq -r .validators[0].pub_key.value)

substitute_dev_conf "${STAKING_ADDRESS}" "1.1" "1.25" "${VALIDATOR_PUB_KEY}" "${GENESIS_TIME}" "./dev-conf-fee.json"
