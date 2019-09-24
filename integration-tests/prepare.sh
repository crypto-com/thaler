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

function git_clone_chain_tx_enclave() {
    if [ -d "${CHAIN_TX_ENCLAVE_DIRECTORY}" ]; then
        CWD=$(pwd)
        cd "${CHAIN_TX_ENCLAVE_DIRECTORY}" && git pull
        cd "${CWD}"
    else
        git clone https://github.com/crypto-com/chain-tx-enclave.git "${CHAIN_TX_ENCLAVE_DIRECTORY}"
    fi
}

function build_chain_tx_enclave_docker_image() {
    CWD=$(pwd)
    cd "${CHAIN_TX_ENCLAVE_DIRECTORY}" && docker build -t "${CHAIN_TX_ENCLAVE_DOCKER_IMAGE}" \
        -f ./tx-validation/Dockerfile . \
        --build-arg SGX_MODE=SW \
        --build-arg NETWORK_ID="${CHAIN_HEX_ID}"
    cd "${CWD}"
}

function init_tendermint() {
    print_config "TENDERMINT_VERSION" "${TENDERMINT_VERSION}"
    rm -rf ./tendermint
    mkdir -p ./tendermint
    if [ ! -z "${CI}" ]; then
        chmod 777 ./tendermint
    fi
    docker run -v "$(pwd)/tendermint:/tendermint" --env TMHOME=/tendermint "tendermint/tendermint:v${TENDERMINT_VERSION}" init
    if [ ! -z "${CI}" ]; then
        sudo chmod -R 777 ./tendermint
    fi

    index_all_tags "tendermint"
}

# @argument Tendermint directory
function index_all_tags() {
    print_step "Enable tag indexing for ${1}"
    cat "${1}/config/config.toml" | sed "s/index_all_tags = false/index_all_tags = true/g" | tee "${1}/config/config.toml" > /dev/null
}

# @argument Tendermint directory
function clone_tendermint_config() {
    rm -rf "${1}"
    mkdir -p "${1}"
    cp -r ./tendermint/. "${1}"
}

# Create wallet
# @argument Wallet Name
# @argument Wallet Passphrase
function create_wallet() {
    rm -rf "${WALLET_STORAGE_DIRECTORY}"
    print_step "Creating wallet \"${1}\""
    RET_VALUE=$(printf "${2}\n${2}\n" | CRYPTO_CLIENT_STORAGE=${WALLET_STORAGE_DIRECTORY} ../target/debug/client-cli wallet new --name ${1})
}

# Create wallet staking address
# @argument Wallet Name
# @argument Wallet Passphrase
function create_wallet_staking_address() {
    print_step "Creating staking address for wallet \"${1}\""
    printf "${2}\n" | CRYPTO_CHAIN_ID=${CHAIN_ID} CRYPTO_CLIENT_STORAGE=${WALLET_STORAGE_DIRECTORY} ../target/debug/client-cli address new --name ${1} --type Staking

    print_step "Retrieving last staking address for wallet \"${1}\""
    ADDRESS_LIST=$(printf "${2}\n" | CRYPTO_CHAIN_ID=${CHAIN_ID} CRYPTO_CLIENT_STORAGE=${WALLET_STORAGE_DIRECTORY} ../target/debug/client-cli address list --name ${1} --type Staking)
    RET_VALUE=$(echo $ADDRESS_LIST | tail -n1 | sed -En "s/^.*(0x[0-9a-zA-Z]+).*$/\1/p")
}

# Create wallet staking address
# @argument Wallet Name
# @argument Wallet Passphrase
function create_wallet_transfer_address() {
    print_step "Creating transfer address for wallet \"${1}\""
    printf "${2}\n" | CRYPTO_CHAIN_ID=${CHAIN_ID} CRYPTO_CLIENT_STORAGE=${WALLET_STORAGE_DIRECTORY} ../target/debug/client-cli address new --name ${1} --type Transfer

    print_step "Retrieving last transfer address for wallet \"${1}\""
    ADDRESS_LIST=$(printf "${2}\n" | CRYPTO_CHAIN_ID=${CHAIN_ID} CRYPTO_CLIENT_STORAGE=${WALLET_STORAGE_DIRECTORY} ../target/debug/client-cli address list --name ${1} --type Transfer)
    echo "${ADDRESS_LIST}"
    RET_VALUE=$(echo $ADDRESS_LIST | tail -n1 | sed -En "s/^.*(dcro[0-9a-zA-Z]+).*$/\1/p")
}

# Save wallet addresses into JSON file
# @argument Staking address
# @argument Transfer address 1
# @argument Transfer address 1
function save_wallet_addresses() {
    echo "${ADDRESS_STATE_TEMPLATE}" | \
        jq --arg ADDRESS "${1}" '.staking=($ADDRESS)' | \
        jq --arg ADDRESS "${2}" '.transfer[0]=($ADDRESS)' | \
        jq --arg ADDRESS "${3}" '.transfer[1]=($ADDRESS)' | \
        tee ${ADDRESS_STATE_PATH} > /dev/null
}

ADDRESS_STATE_TEMPLATE=$(cat << EOF
{
	"staking": "{STAKING_ADDRESS}",
    "transfer": [
        "{TRANSFER_ADDRESS_1}",
        "{TRANSFER_ADDRESS_2}"
    ]
}
EOF
)

DEV_CONF=$(cat << EOF
{
    "distribution": {
        "{STAKING_ADDRESS}": "2500000000000000000",
        "0x20a0bee429d6907e556205ef9d48ab6fe6a55531": "2500000000000000000",
        "0x35f517cab9a37bc31091c2f155d965af84e0bc85": "2500000000000000000",
        "0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de": "1250000000000000000",
        "0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07": "1250000000000000000"
    },
    "unbonding_period": 5,
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
# @argument Chain ID
function generate_tendermint_genesis() {
    print_step "Generating Tendermint genesis ${1} -> ${2}"
    _generate_genesis "${1}"; GENESIS_JSON="${RET_VALUE}"

    TENDERMINT_GENESIS_JSON=$(cat "${2}/config/genesis.json")
    _append_genesis_to_tendermint_genesis "${TENDERMINT_GENESIS_JSON}" "${GENESIS_JSON}"
    _change_tenermint_chain_id "${RET_VALUE}" "${3}"

    echo "${RET_VALUE}" > "${2}/config/genesis.json"
}

# @argument Dev uilts config path
function _generate_genesis() {
    RET_VALUE=$(../target/debug/dev-utils genesis generate -g "${1}")
}

# @argument Tendermint genesis JSON
# @argument Genesis JSON generated
function _append_genesis_to_tendermint_genesis() {
    # Find the line of occurence of last }
    APP_HASH_LINE_NUMBER=$(echo "${1}" | awk '/app_hash/{print NR}' | tail -n1)
    # Append generated JSON after the line
    GENESIS_PREFIX=$(echo "${1}" | head -n$(($APP_HASH_LINE_NUMBER - 1)))
    RET_VALUE="${GENESIS_PREFIX}${2}}"
}

# @argument Tendermint genesis JSON
# @argument Chain ID
function _change_tenermint_chain_id() {
    RET_VALUE=$(echo "${1}" | jq --arg CHAIN_ID "${CHAIN_ID}" '.chain_id=($CHAIN_ID)')
}

# Always execute at script located directory
cd "$(dirname "${0}")"

# Source constants
. ./constant-env.sh

check_command_exist "jq"
check_command_exist "git"
check_command_exist "cargo"

print_step "cargo build"
cargo build

print_step "git update Chain Transaction Enclave"
git_clone_chain_tx_enclave
if [ -z "${CI}" ]; then
    print_step "Build Chain Transaction Enclave image"
    build_chain_tx_enclave_docker_image
fi

print_step "Initialize Tendermint"
init_tendermint

print_step "Clone Tendermint configuration"
clone_tendermint_config "${TENDERMINT_WITHFEE_DIRECTORY}"
clone_tendermint_config "${TENDERMINT_ZEROFEE_DIRECTORY}"

print_step "Generate wallet and addresses"
create_wallet "Default" "${WALLET_PASSPHRASE}"
create_wallet_staking_address "Default" "${WALLET_PASSPHRASE}"; STAKING_ADDRESS="${RET_VALUE}"
create_wallet_transfer_address "Default" "${WALLET_PASSPHRASE}"; TRANSFER_ADDRESS_1="${RET_VALUE}"
create_wallet_transfer_address "Default" "${WALLET_PASSPHRASE}"; TRANSFER_ADDRESS_2="${RET_VALUE}"
print_config "STAKING_ADDRESS" "${STAKING_ADDRESS}"
print_config "TRANSFER_ADDRESS_1" "${TRANSFER_ADDRESS_1}"
print_config "TRANSFER_ADDRESS_2" "${TRANSFER_ADDRESS_2}"
save_wallet_addresses "${STAKING_ADDRESS}" "${TRANSFER_ADDRESS_1}" "${TRANSFER_ADDRESS_2}"

print_step "Generate Tendermint genesis"
VALIDATOR_PUB_KEY=$(cat ./tendermint/config/genesis.json | jq -r .validators[0].pub_key.value)
GENESIS_TIME=$(cat ./tendermint/config/genesis.json | jq -r .genesis_time)
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
		sed "s/{GENESIS_TIME}/${GENESIS_TIME}/g" | tee ${3} > /dev/null
}

generate_dev_conf "1.1" "1.25" "${DEV_CONF_WITHFEE_PATH}"
generate_dev_conf "0.0" "0.0" "${DEV_CONF_ZEROFEE_PATH}"

generate_tendermint_genesis "${DEV_CONF_WITHFEE_PATH}" "${TENDERMINT_WITHFEE_DIRECTORY}" "${CHAIN_ID}"
generate_tendermint_genesis "${DEV_CONF_ZEROFEE_PATH}" "${TENDERMINT_ZEROFEE_DIRECTORY}" "${CHAIN_ID}"

sleep 5
