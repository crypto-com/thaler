#!/bin/bash
set -e

BUILD_PROFILE=${BUILD_PROFILE:-debug}
BUILD_MODE=${BUILD_MODE:-sgx}

if [ $BUILD_PROFILE == "debug" ]; then
    CARGO_ARGS=
else
    CARGO_ARGS=--release
fi

echo "Test $BUILD_MODE $BUILD_PROFILE"
if [ $BUILD_MODE == "sgx" ]; then
    cargo test $CARGO_ARGS
else
    cargo test $CARGO_ARGS --features mock-enclave --manifest-path client-rpc/Cargo.toml
    cargo test $CARGO_ARGS --features mock-enclave --manifest-path client-cli/Cargo.toml
    cargo test $CARGO_ARGS --features mock-enclave --manifest-path dev-utils/Cargo.toml
    cargo test $CARGO_ARGS --features mock-enclave --manifest-path chain-abci/Cargo.toml
    for pkg in \
        client-common \
        client-network \
        client-core \
        test-common \
        enclave-protocol \
        chain-core \
        chain-storage \
        chain-tx-filter \
        chain-tx-validation
    do
        cargo test $CARGO_ARGS --manifest-path $pkg/Cargo.toml
    done
fi
