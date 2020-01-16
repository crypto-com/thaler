#!/bin/bash
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

MOCK_CHAIN=${MOCK_CHAIN:-0}

cd ..
if [ $MOCK_CHAIN -eq 1 ]; then
    cargo build --features mock-enc-dec --manifest-path client-cli/Cargo.toml
    cargo build --features mock-enc-dec --manifest-path client-rpc/Cargo.toml
    cargo build --features mock-enc-dec --features mock-validation --manifest-path chain-abci/Cargo.toml
    cargo build -p dev-utils
else
    SGX_SDK=${SGX_SDK-:/opt/intel/sgxsdk}
    source $SGX_SDK/environment

    cargo build
    cargo build -p tx-validation-app
    cargo build -p tx-query-app
    make -C chain-tx-enclave/tx-validation
    make -C chain-tx-enclave/tx-query
fi
