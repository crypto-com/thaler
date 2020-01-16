#!/bin/bash
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

source $SGX_SDK/environment

cd ..
cargo build
cargo build -p tx-validation-app
cargo build -p tx-query-app
make -C chain-tx-enclave/tx-validation
make -C chain-tx-enclave/tx-query
