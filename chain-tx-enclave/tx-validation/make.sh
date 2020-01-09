#!/bin/bash
set -e

source /root/.docker_bashrc
cargo build -p tx-validation-app
make -C chain-tx-enclave/tx-validation
