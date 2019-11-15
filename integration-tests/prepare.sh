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

function build_chain_docker_image() {
    CWD=$(pwd)
    cd ../ && docker build -t "${CHAIN_DOCKER_IMAGE}" -f ./docker/Dockerfile .
    cd "${CWD}"
}

function build_chain_tx_enclave_docker_image() {
    print_config "SGX_MODE" "${SGX_MODE}"
    CWD=$(pwd)
    cd ../ && docker build -t "${CHAIN_TX_ENCLAVE_DOCKER_IMAGE}" \
        -f ./chain-tx-enclave/tx-validation/Dockerfile . \
        --build-arg SGX_MODE="${SGX_MODE}" \
        --build-arg NETWORK_ID="${CHAIN_HEX_ID}"
    cd "${CWD}"
}

# @argument Tendermint directory
function init_tendermint() {
    mkdir -p "${1}"

    print_config "TENDERMINT_VERSION" "${TENDERMINT_VERSION}"
    docker run --rm -v "$(pwd)/${1}:/tendermint" --env TMHOME=/tendermint --user "$(id -u):$(id -g)" "tendermint/tendermint:v${TENDERMINT_VERSION}" init

    sync

    index_all_tags "${1}"
}

# @argument Tendermint directory
function index_all_tags() {
    print_step "Enable tag indexing for ${1}"
    sed -i -e "s/index_all_tags = false/index_all_tags = true/g" "${1}/config/config.toml"

    sync
}

# @argument original Tendermint directory
# @argument Cloned Tendermint directory
function clone_tendermint_config() {
    print_step "Cloning Tendermint config from \"${1}\" to \"${2}\""

    rm -rf "${2}"
    mkdir -p "${2}"
    cp -r "${1}/." "${2}"
}

# Create wallet
# @argument Wallet Name
# @argument Wallet Passphrase
# @argument Wallet storage directory
function create_wallet() {
    mkdir -p "${3}"

    print_step "Creating wallet \"${1}\""
    if [ -z "${USE_DOCKER_COMPOSE}" ]; then
        RET_VALUE=$(printf "${2}\n${2}\n" | CRYPTO_CLIENT_STORAGE="${3}" ../target/debug/client-cli wallet new --name "${1}" --type basic)
    else
        RET_VALUE=$(printf "${2}\n${2}\n" | docker run -i --rm -v "$(pwd)/${3}:/.storage" --env CRYPTO_CLIENT_STORAGE=/.storage --user "$(id -u):$(id -g)" "${CHAIN_DOCKER_IMAGE}" client-cli wallet new --name "${1}" --type basic)
    fi
}

# Create wallet staking address
# @argument Wallet Name
# @argument Wallet Passphrase
# @argument Wallet storage directory
function create_wallet_staking_address() {
    print_step "Creating staking address for wallet \"${1}\""
    if [ -z "${USE_DOCKER_COMPOSE}" ]; then
        RESULT=$(printf "${2}\n" | CRYPTO_CHAIN_ID=${CHAIN_ID} CRYPTO_CLIENT_STORAGE=${3} ../target/debug/client-cli address new --name ${1} --type Staking)
    else
        RESULT=$(printf "${2}\n" | docker run -i --rm -v "$(pwd)/${3}:/.storage" --env CRYPTO_CHAIN_ID=${CHAIN_ID} --env CRYPTO_CLIENT_STORAGE=/.storage --user "$(id -u):$(id -g)" "${CHAIN_DOCKER_IMAGE}" client-cli address new --name ${1} --type Staking)
    fi
    echo "${RESULT}"
    RET_VALUE=$(echo "${RESULT}" | sed -En "s/^.*(0x[0-9a-zA-Z]+).*$/\1/p")
}

# Create wallet staking address
# @argument Wallet Name
# @argument Wallet Passphrase
# @argument Wallet storage directory
function create_wallet_transfer_address() {
    print_step "Creating transfer address for wallet \"${1}\""
    if [ -z "${USE_DOCKER_COMPOSE}" ]; then
        RESULT=$(printf "${2}\n" | CRYPTO_CHAIN_ID=${CHAIN_ID} CRYPTO_CLIENT_STORAGE=${3} ../target/debug/client-cli address new --name ${1} --type Transfer)
    else
        RESULT=$(printf "${2}\n" | docker run -i --rm -v "$(pwd)/${3}:/.storage" --env CRYPTO_CHAIN_ID=${CHAIN_ID} --env CRYPTO_CLIENT_STORAGE=/.storage --user "$(id -u):$(id -g)" "${CHAIN_DOCKER_IMAGE}" client-cli address new --name ${1} --type Transfer)
    fi
    echo "${RESULT}"
    RET_VALUE=$(echo "${RESULT}" | tail -n1 | sed -En "s/^.*(dcro[0-9a-zA-Z]+).*$/\1/p")
}

# Clone wallet storage to specified location
# @argument Original wallet directory
# @argument Cloned wallet directory
function clone_wallet() {
    print_step "Cloning wallet from \"${1}\" to \"${2}\""

    rm -rf "${2}"
    mkdir -p "${2}"
    cp -r "${1}/." "${2}/"
}

# Save wallet addresses into JSON file
# @argument Staking address
# @argument Transfer address 1
# @argument Transfer address 2
function save_wallet_addresses() {
    echo "${ADDRESS_STATE_TEMPLATE}" | \
        jq --arg ADDRESS "${1}" '.staking=($ADDRESS)' | \
        jq --arg ADDRESS "${2}" '.transfer[0]=($ADDRESS)' | \
        jq --arg ADDRESS "${3}" '.transfer[1]=($ADDRESS)' > ${ADDRESS_STATE_PATH}
    
    sync
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
    "rewards_pool": "6250000000000000000",
    "distribution": {
        "{STAKING_ADDRESS}": "2500000000000000000",
        "0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de": "1250000000000000000"
    },
    "unbonding_period": 15,
    "required_council_node_stake": "1250000000000000000",
    "jailing_config": {
        "jail_duration": 86400,
        "block_signing_window": 100,
        "missed_block_threshold": 50
    },
    "slashing_config": {
        "liveness_slash_percent": "0.1",
        "byzantine_slash_percent": "0.2",
        "slash_wait_period": 10800
    },
    "initial_fee_policy": {
        "base_fee": "{BASE_FEE}",
        "per_byte_fee": "{PER_BYTE_FEE}"
    },
    "council_nodes": {
        "0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de": [
            "integration test",
            "security@integration.test",
        {
            "consensus_pubkey_type": "Ed25519",
            "consensus_pubkey_b64": "{PUB_KEY}"
        }]
    },
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

    sync
}

# @argument Dev uilts config path
function _generate_genesis() {
    if [ -z "${USE_DOCKER_COMPOSE}" ]; then
        RET_VALUE=$(../target/debug/dev-utils genesis generate -g "${1}")
    else
        RET_VALUE=$(docker run -i --rm -v "$(pwd):/.genesis" "${CHAIN_DOCKER_IMAGE}" dev-utils genesis generate -g "/.genesis/${1}")
    fi
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
cd "$(dirname "${BASH_SOURCE[0]}")"

# Source constants
. ./const-env.sh

check_command_exist "jq"
check_command_exist "git"

if [ ! -z "${CI}" ]; then
    USE_DOCKER_COMPOSE=1
fi

if [ -z "${USE_DOCKER_COMPOSE}" ]; then
    check_command_exist "cargo"
fi

# allow current user to access docker data directory 
chmod ug+s "${DOCKER_DATA_DIRECTORY}"

print_step "Build Chain image"
if [ ! -z "${USE_DOCKER_COMPOSE}" ]; then
    build_chain_docker_image
else
    cargo build
fi

print_step "Build Chain Transaction Enclave image"
build_chain_tx_enclave_docker_image

print_step "Initialize Tendermint"
rm -rf "${TENDERMINT_TEMP_DIRECTORY}"
init_tendermint "${TENDERMINT_TEMP_DIRECTORY}"

print_step "Clone Tendermint configuration"
clone_tendermint_config "${TENDERMINT_TEMP_DIRECTORY}" "${TENDERMINT_WITHFEE_DIRECTORY}"
clone_tendermint_config "${TENDERMINT_TEMP_DIRECTORY}" "${TENDERMINT_ZEROFEE_DIRECTORY}"

print_step "Generate wallet and addresses"
rm -rf "${WALLET_STORAGE_TEMP_DIRECTORY}"
create_wallet "Default" "${WALLET_PASSPHRASE}" "${WALLET_STORAGE_TEMP_DIRECTORY}"
create_wallet_staking_address "Default" "${WALLET_PASSPHRASE}" "${WALLET_STORAGE_TEMP_DIRECTORY}"; STAKING_ADDRESS="${RET_VALUE}"
create_wallet_transfer_address "Default" "${WALLET_PASSPHRASE}" "${WALLET_STORAGE_TEMP_DIRECTORY}"; TRANSFER_ADDRESS_1="${RET_VALUE}"
create_wallet_transfer_address "Default" "${WALLET_PASSPHRASE}" "${WALLET_STORAGE_TEMP_DIRECTORY}"; TRANSFER_ADDRESS_2="${RET_VALUE}"
print_config "STAKING_ADDRESS" "${STAKING_ADDRESS}"
print_config "TRANSFER_ADDRESS_1" "${TRANSFER_ADDRESS_1}"
print_config "TRANSFER_ADDRESS_2" "${TRANSFER_ADDRESS_2}"
clone_wallet "${WALLET_STORAGE_TEMP_DIRECTORY}" "${WALLET_STORAGE_WITHFEE_DIRECTORY}"
clone_wallet "${WALLET_STORAGE_TEMP_DIRECTORY}" "${WALLET_STORAGE_ZEROFEE_DIRECTORY}"
save_wallet_addresses "${STAKING_ADDRESS}" "${TRANSFER_ADDRESS_1}" "${TRANSFER_ADDRESS_2}"

print_step "Generate Tendermint genesis"
VALIDATOR_PUB_KEY=$(cat "${TENDERMINT_TEMP_DIRECTORY}/config/genesis.json" | jq -r .validators[0].pub_key.value)
GENESIS_TIME=$(cat "${TENDERMINT_TEMP_DIRECTORY}/config/genesis.json" | jq -r .genesis_time)
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

    sync
}

generate_dev_conf "1.1" "1.25" "${DEVCONF_WITHFEE_PATH}"
generate_dev_conf "0.0" "0.0" "${DEVCONF_ZEROFEE_PATH}"

generate_tendermint_genesis "${DEVCONF_WITHFEE_PATH}" "${TENDERMINT_WITHFEE_DIRECTORY}" "${CHAIN_ID}"
generate_tendermint_genesis "${DEVCONF_ZEROFEE_PATH}" "${TENDERMINT_ZEROFEE_DIRECTORY}" "${CHAIN_ID}"

sync
