#!/usr/bin/env bash
set -e

rustup default nightly-2019-08-01-x86_64-unknown-linux-gnu

# Build test environment
cd integration-tests
./prepare.sh || exit 1
. ./env.sh
docker-compose down || exit 1
docker-compose up -d || exit 1

sleep 30

# Docker status
docker ps
docker-compose logs -t --tail="all"

# Preliminary tests
./run-test.sh || exit 1

# Integration tests
cd client-rpc
npm install
npm run test || exit 1

# Docker status after tests
docker ps

# Teardown
docker-compose down
