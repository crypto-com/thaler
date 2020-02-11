#!/bin/bash
set -e

source /root/.docker_bashrc
cargo build -p chain-abci
make -C chain-tx-enclave/tx-validation
