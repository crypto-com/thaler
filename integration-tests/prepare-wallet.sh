#!/usr/bin/env bash

# Working Directory
cd "$(dirname "${0}")"

CLIENT_RPC_URL="http://${1:-localhost}:${2:-9981}"

DEFAULT_PASSPHRASE="uV97tEs5!*lLRQKj"
GENESIS_DISTRIBUTION_MAPPING_PATH="docker/tendermint-preinit/genesis_distribution_mapping"
ADDRESS_LIST_PATH="address-list.json"

GENESIS_DISTRIBUTION_MAPPING_TEMPLATE=$(cat << EOF
{DEFAULT_ADDRESS} 2500000000000000000
{SPEND_ADDRESS} 3000000000000000000
{VIEW_ADDRESS} 3000000000000000000
0x35f517cab9a37bc31091c2f155d965af84e0bc85 500000000000000000
0x20a0bee429d6907e556205ef9d48ab6fe6a55531 500000000000000000
0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07 500000000000000000
EOF
)
ADDRESS_LIST_TEMPLATE=$(cat << EOF
{
	"default": "{DEFAULT_ADDRESS}",
	"spend": "{SPEND_ADDRESS}",
	"view": "{VIEW_ADDRESS}",
	"receive": "{RECEIVE_ADDRESS}"
}
EOF
)

# @argument Wallet Name
# @argument Wallet Passphrase
function create_wallet() {
	RESPONSE=$(curl -SsX POST \
		${CLIENT_RPC_URL}/ \
		-H 'Content-Type: application/json' \
		-d '{
		"method": "wallet_create",
		"jsonrpc": "2.0",
		"params": [{
			"name": "'${1}'",
			"passphrase": "'${2}'"
		}],
		"id": "wallet_create"
	}')

	RESULT=$(echo $RESPONSE | jq -r .result)
	if [ "x${RESULT}" = "xnull" ]; then
		ERROR_MESSAGE=$(echo $RESPONSE | jq -r .error.message)
		if ! [ "x${ERROR_MESSAGE}" = "xAlready exists in storage" ] ; then
			echo "Error: Cannot create wallet ${1} ${RESPONSE}" >&2
			exit 1
		fi
	else
		echo "Created wallet ${1}"
	fi
}

# @argument Wallet Name
# @argument Wallet Passphrase
function get_wallet_address() {
	RESPONSE=$(curl -SsX POST \
		"${CLIENT_RPC_URL}/" \
		-H 'Content-Type: application/json' \
		-H 'Host: localhost:26659' \
		-d '{
		"method": "wallet_addresses",
		"jsonrpc": "2.0",
		"params": [{
			"name": "'"${1}"'",
			"passphrase": "'"${2}"'"
		}],
		"id": "wallet_addresses"
	}')

	RESULT=$(echo "${RESPONSE}" | jq -r .result)
	if [ "x${RESULT}" = "xnull" ]; then
		echo "Error: Cannot get wallet ${1} address ${RESPONSE}" >&2
		exit 1
	else
		echo "${RESPONSE}" | jq -r .result[0]
	fi
}

# @argument Template
# @argument Ouput File Path
function substitute_address_to_file() {
	echo "${1}" | \
		sed "s/{DEFAULT_ADDRESS}/${DEFAULT_ADDRESS}/g" | \
		sed "s/{SPEND_ADDRESS}/${SPEND_ADDRESS}/g" | \
		sed "s/{VIEW_ADDRESS}/${VIEW_ADDRESS}/g" | \
		sed "s/{RECEIVE_ADDRESS}/${RECEIVE_ADDRESS}/g" > "${2}"
	echo "Generated file ${2}"
}

function test_client_rpc() {
	set -e
	curl -SX POST \
	"${CLIENT_RPC_URL}/" \
	-H 'Content-Type: application/json' \
	-d '{
		"method": "wallet_list",
		"jsonrpc": "2.0",
		"params": [],
		"id": "wallet_list"
	}' > /dev/null
	set +e
}

echo "Client RPC URL: ${CLIENT_RPC_URL}"
test_client_rpc

create_wallet Default "${DEFAULT_PASSPHRASE}"
create_wallet Spend "${DEFAULT_PASSPHRASE}"
create_wallet View "${DEFAULT_PASSPHRASE}"
create_wallet Receive "${DEFAULT_PASSPHRASE}"

DEFAULT_ADDRESS=$(get_wallet_address Default "${DEFAULT_PASSPHRASE}")
SPEND_ADDRESS=$(get_wallet_address Spend "${DEFAULT_PASSPHRASE}")
VIEW_ADDRESS=$(get_wallet_address View "${DEFAULT_PASSPHRASE}")
RECEIVE_ADDRESS=$(get_wallet_address Receive "${DEFAULT_PASSPHRASE}")

substitute_address_to_file "${GENESIS_DISTRIBUTION_MAPPING_TEMPLATE}" "${GENESIS_DISTRIBUTION_MAPPING_PATH}"
substitute_address_to_file "${ADDRESS_LIST_TEMPLATE}" "${ADDRESS_LIST_PATH}"

echo "Remember to copy and replace the generated Client RPC wallet storage .cro-rpc-storage to docker/chain-preinit/"
