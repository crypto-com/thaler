#!/usr/bin/env bash
set -ex

rustup default nightly-2019-08-01-x86_64-unknown-linux-gnu

# Build test environment
cd integration-tests
./prepare.sh || exit 1
. ./env.sh
docker-compose down || exit 1

docker-compose up -d || exit 1

./wait-for-setup.sh || (docker ps && docker-compose logs -t --tail="all" && exit 1)

# Preliminary tests
./run-test.sh || (docker ps && docker-compose logs -t --tail="all" && exit 1)

# Integration tests
cd client-rpc
npm install
npm run test || (docker ps && docker-compose logs -t --tail="all" && exit 1)

# Teardown
docker-compose down
