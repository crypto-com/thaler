#!/usr/bin/env bash
set -e
IFS=

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

if [ -z "${FEE_SCHEMA}" ]; then
  print_error "Missing Fee Schema"
  exit 1
fi
if [ -z "${PROXY_APP}" ]; then
  print_error "Missing Tendermint Proxy App"
  exit 1
fi

print_config "FEE_SCHEMA" "${FEE_SCHEMA}"
print_config "PROXY_APP" "${PROXY_APP}"

if [ "x${FEE_SCHEMA}" = "xWITHFEE" ]; then
  cp -r ./tendermint-withfee/* "${TMHOME}"
elif [ "x${FEE_SCHEMA}" = "xZEROFEE" ]; then
  cp -r ./tendermint-zerofee/* "${TMHOME}"
else
  print_error "Unsupported Fee Schema: ${FEE_SCHEMA}"
  exit 1
fi

print_step "Starting Tendermint"
/usr/bin/tendermint node --proxy_app=${PROXY_APP} --rpc.laddr=tcp://0.0.0.0:26657 --consensus.create_empty_blocks=true
