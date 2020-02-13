#!/bin/bash
set -e

BUILD_PROFILE=${BUILD_PROFILE:-debug}
BUILD_MODE=${BUILD_MODE:-sgx}

echo "Test $BUILD_MODE $BUILD_PROFILE"
if [ $BUILD_MODE == "sgx" ]; then
    cargo test $CARGO_ARGS
else
    cargo test $CARGO_ARGS --features mock-enc-dec  --manifest-path client-rpc/Cargo.toml
    cargo test $CARGO_ARGS --features mock-enc-dec  --manifest-path client-cli/Cargo.toml
    cargo test $CARGO_ARGS --features mock-enc-dec --features mock-validation --manifest-path dev-utils/Cargo.toml
    cargo test $CARGO_ARGS --features mock-enc-dec --features mock-validation --manifest-path chain-abci/Cargo.toml
fi
