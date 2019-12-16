#!/usr/bin/env bash
set -ex

# Build test environment
cd integration-tests
./prepare.sh || exit 1
. ./env.sh
docker-compose -p "${DOCKER_COMPOSE_PREFIX}" down || (docker ps; exit 1)

# Find ports for Docker
export TENDERMINT_RPC_PORT=$(../ci-scripts/find-free-port.sh)
export CLIENT_RPC_PORT=$(../ci-scripts/find-free-port.sh)
export TENDERMINT_ZEROFEE_RPC_PORT=$(../ci-scripts/find-free-port.sh)
export CLIENT_RPC_ZEROFEE_PORT=$(../ci-scripts/find-free-port.sh)

docker-compose -p "${DOCKER_COMPOSE_PREFIX}" up -d || (docker ps; exit 1)

./wait-for-setup.sh || (docker ps; docker-compose -p "${DOCKER_COMPOSE_PREFIX}" logs -t --tail="all"; exit 1)

# Preliminary tests
./run-test.sh || (docker ps; docker-compose -p "${DOCKER_COMPOSE_PREFIX}" logs -t --tail="all"; exit 1)

# Integration tests
cd client-rpc
npm install
npm run test || (docker ps; docker-compose -p "${DOCKER_COMPOSE_PREFIX}" logs -t --tail="all"; exit 1)

# Python integration tests. prisoned for now, waiting for it's hero.
# cd ../bot
# pip3 install -e .
# pip3 install pytest
# export PASSPHRASE=${WALLET_PASSPHRASE:-123456}
# CHAIN_RPC_URL=http://127.0.0.1:$TENDERMINT_ZEROFEE_RPC_PORT CLIENT_RPC_URL=http://127.0.0.1:$CLIENT_RPC_ZEROFEE_PORT pytest tests
