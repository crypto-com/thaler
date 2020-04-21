#!/bin/bash
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

if [ -f $SGX_SDK/environment ]; then
    source $SGX_SDK/environment
fi

BUILD_PROFILE=${BUILD_PROFILE:-debug}
BUILD_MODE=${BUILD_MODE:-sgx}

if [ $BUILD_PROFILE == "debug" ]; then
    export SGX_DEBUG=1
    CARGO_ARGS=
else
    export SGX_DEBUG=0
    CARGO_ARGS=--release
fi

cd ..
echo "Build $BUILD_MODE $BUILD_PROFILE"
if [ $BUILD_MODE == "sgx" ]; then
    cargo build $CARGO_ARGS
    cargo build $CARGO_ARGS -p tx-query-app
    make -C chain-tx-enclave/tx-validation
    make -C chain-tx-enclave/tx-query
else
    cargo build $CARGO_ARGS --features mock-enclave --manifest-path client-rpc/Cargo.toml
    cargo build $CARGO_ARGS --features mock-enclave --manifest-path client-cli/Cargo.toml
    cargo build $CARGO_ARGS --features mock-enclave --manifest-path cro-clib/Cargo.toml
    cargo build $CARGO_ARGS --features mock-enclave --manifest-path dev-utils/Cargo.toml
    cargo build $CARGO_ARGS --features mock-enclave --manifest-path chain-abci/Cargo.toml
fi
