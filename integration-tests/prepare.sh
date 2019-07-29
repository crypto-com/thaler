#!/usr/bin/env bash
set -e
IFS=

TENDERMINT_PATH=${TENDERMINT_PATH:-tendermint}
WALLET_PASSPHRASE=${WALLET_PASSPHRASE:-123456}
TENDERMINT_VERSION=${TENDERMINT_VERSION:-latest}

# Do not modify the following constants
WALLET_TEMP_PATH="./chain/wallet-storage"
DEV_CONF_WITHFEE_PATH="./dev-conf-withfee.json"
DEV_CONF_ZEROFEE_PATH="./dev-conf-zerofee.json"
TENDERMINT_TEMP_DIRECTORY="./tendermint"
TENDERMINT_WITHFEE_DIRECTORY="./docker/tendermint/tendermint-withfee"
TENDERMINT_ZEROFEE_DIRECTORY="./docker/tendermint/tendermint-zerofee"

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
    RET_VALUE=$(printf "${2}\n" | ../target/debug/client-cli wallet new --name ${1})
}

# Create wallet staking address
# @argument Wallet Name
# @argument Wallet Passphrase
function create_wallet_staking_address() {
    print_step "Creating address for wallet \"${1}\""
    printf "${2}\n" | ../target/debug/client-cli address new --name ${1} --type Staking

    print_step "Retrieving last address for wallet \"${1}\""
    ADDRESS_LIST=$(printf "${2}\n" | ../target/debug/client-cli address list --name ${1} --type Staking)
    echo "${ADDRESS_LIST}"
    RET_VALUE=$(echo $ADDRESS_LIST | tail -n2 | sed -En "s/^.*(0x[0-9a-zA-Z]+)/\1/p")
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

# @argument Dev uilts config path
# @argument Tendermint directory
function generate_tendermint_genesis() {
    print_step "Generating Tendermint genesis ${1} -> ${2}"
    _generate_genesis "${1}"; GENESIS_JSON="${RET_VALUE}"
    _append_genesis_to_tendermint_genesis "${2}" "${GENESIS_JSON}"
}

# @argument Dev uilts config path
function _generate_genesis() {
    RET_VALUE=$(../target/debug/dev-utils genesis generate -g "${1}")
}

# @argument Tendermint directory
# @argument Genesis JSON generated
function _append_genesis_to_tendermint_genesis() {
    # Find the line of occurence of last }
    APP_HASH_LINE_NUMBER=$(cat "${1}/config/genesis.json" | awk '/app_hash/{print NR}' | tail -n1)
    # Append generated JSON after the line
    GENESIS_PREFIX=$(cat "${1}/config/genesis.json" | head -n$(($APP_HASH_LINE_NUMBER - 1)))
    echo "${GENESIS_PREFIX}${2}}" > "${1}/config/genesis.json"
}

# Change working directory
cd "$(dirname "${0}")"

check_command_exist "jq"
check_command_exist "../target/debug/client-cli"
check_command_exist "../target/debug/dev-utils"

print_step "Tendermint init"
print_config "TENDERMINT_VERSION" "${TENDERMINT_VERSION}"
docker run -v "$(pwd)/tendermint:/tendermint" --env TMHOME=/tendermint "tendermint/tendermint:v${TENDERMINT_VERSION}" init

print_step "Clone Tendermint configuration"
mkdir -p "${TENDERMINT_WITHFEE_DIRECTORY}"; cp -r ./tendermint/. "${TENDERMINT_WITHFEE_DIRECTORY}"
mkdir -p "${TENDERMINT_ZEROFEE_DIRECTORY}"; cp -r ./tendermint/. "${TENDERMINT_ZEROFEE_DIRECTORY}"

create_wallet "Default" "${WALLET_PASSPHRASE}"

create_wallet_staking_address "Default" "${WALLET_PASSPHRASE}"; STAKING_ADDRESS="${RET_VALUE}"
VALIDATOR_PUB_KEY=$(cat ~/.tendermint/config/genesis.json | jq -r .validators[0].pub_key.value)
GENESIS_TIME=$(cat ~/.tendermint/config/genesis.json | jq -r .genesis_time)
print_config "STAKING_ADDRESS" "${STAKING_ADDRESS}"
print_config "VALIDATOR_PUR_KEY" "${VALIDATOR_PUB_KEY}"
print_config "GENESIS_TIME" "${GENESIS_TIME}"

# @argument Base Fee
# @argument Per Byte Fee
# @argument Ouput File Path
function generate_dev_conf() {
    print_step "Generating dev-utils configuration: Base Fee: ${1}, Per Byte Fee: ${2} -> ${3}"
	echo "${DEV_CONF}" | \
		sed "s/{STAKING_ADDRESS}/${STAKING_ADDRESS}/g" | \
		sed "s/{BASE_FEE}/${1}/g" | \
		sed "s/{PER_BYTE_FEE}/${2}/g" | \
        sed "s#{PUB_KEY}#${VALIDATOR_PUB_KEY}#g" | \
		sed "s/{GENESIS_TIME}/${GENESIS_TIME}/g" > ${3}
}

generate_dev_conf "1.1" "1.25" "${DEV_CONF_WITHFEE_PATH}"
generate_dev_conf "0.0" "0.0" "${DEV_CONF_ZEROFEE_PATH}"

generate_tendermint_genesis "${DEV_CONF_WITHFEE_PATH}" "${TENDERMINT_WITHFEE_DIRECTORY}"
generate_tendermint_genesis "${DEV_CONF_ZEROFEE_PATH}" "${TENDERMINT_ZEROFEE_DIRECTORY}"

