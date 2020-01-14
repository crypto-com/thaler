#!/bin/bash
set -e

source /root/.docker_bashrc
cargo build -p tx-query-app
make -C chain-tx-enclave/tx-query
