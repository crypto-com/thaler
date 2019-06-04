#!/usr/bin/env bash
set -e

# Working Directory
cd "$(dirname "${0}")"

LAUNCH_INCENTIVE_FROM="0x35f517cab9a37bc31091c2f155d965af84e0bc85"
LAUNCH_INCENTIVE_TO="0x20a0bee429d6907e556205ef9d48ab6fe6a55531"
LONG_TERM_INCENTIVE="0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07"
TENDERMINT_FEE_GENESIS_PATH="docker/tendermint-preinit/config-template/fee/genesis.json"
TENDERMINT_ZEROFEE_GENESIS_PATH="docker/tendermint-preinit/config-template/zerofee/genesis.json"
INTEGRATION_TESTS_DOCKER_COMPOSE_TEMPLATE_PATH="docker-compose.template.yml"
INTEGRATION_TESTS_DOCKER_COMPOSE_PATH="docker-compose.yml"
GENESIS_TEMPLATE=$(cat << EOF
{
  "genesis_time": "2019-05-21T09:47:56.206264Z",
  "chain_id": "test-chain-y3m1e6-AB",
  "consensus_params": {
    "block": {
      "max_bytes": "22020096",
      "max_gas": "-1",
      "time_iota_ms": "1000"
    },
    "evidence": {
      "max_age": "100000"
    },
    "validator": {
      "pub_key_types": ["ed25519"]
    }
  },
  "validators": [
    {
      "address": "91A26F2D061827567FE1E2ADC1C22206D4AD0FEF",
      "pub_key": {
        "type": "tendermint/PubKeyEd25519",
        "value": "MFgW9OkoKufCrdAjk7Zx0LMWKA/0ixkmuBpO0flyRtU="
      },
      "power": "10",
      "name": ""
    }
  ],
EOF
)

# @argument Base Fee
# @argument Per Byte Fee
function generate_genesis() {
    cd .. && cargo run --package dev-utils -- \
        genesis generate \
        --base_fee "$1" \
        --chain-id AB \
        --launch_incentive_from "${LAUNCH_INCENTIVE_FROM}" \
        --launch_incentive_to "${LAUNCH_INCENTIVE_TO}" \
        --long_term_incentive "${LONG_TERM_INCENTIVE}" \
        --mapping_file_path ./integration-tests/docker/tendermint-preinit/genesis_distribution_mapping \
        --per_byte_fee "$2" | head -n 2
}

# @argument Base Fee
# @argument Per Byte Fee
# @argument Output File Path
function generate_genesis_file() {
  GENESIS=$(echo "${GENESIS_TEMPLATE}$(generate_genesis ${1} ${2})}" | tee "${3}")
  GENESIS_APP_HASH=$(echo "${GENESIS}" | jq -r .app_hash)
  sed "s/{GENESIS_APP_HASH}/${GENESIS_APP_HASH}/g" ${INTEGRATION_TESTS_DOCKER_COMPOSE_TEMPLATE_PATH} > ${INTEGRATION_TESTS_DOCKER_COMPOSE_PATH}

  echo "Generated genesis file ${3}"
}

if ! [ -x "$(command -v jq)" ]; then
  echo 'Error: jq is not installed!' >&2
  exit 1
fi

generate_genesis_file 0.0 0.0 "${TENDERMINT_ZEROFEE_GENESIS_PATH}"
generate_genesis_file 1.55 0.16 "${TENDERMINT_FEE_GENESIS_PATH}"

