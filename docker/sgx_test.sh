#!/bin/bash
set -e


BUILD_PROFILE=${BUILD_PROFILE:-debug}
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"../target"}
EDP_TARGET_DIR=$CARGO_TARGET_DIR/x86_64-fortanix-unknown-sgx/$BUILD_PROFILE

if [ $BUILD_PROFILE == "debug" ]; then
    export SGX_DEBUG=1
    CARGO_ARGS=
    EDP_ARGS=--debug
else
    export SGX_DEBUG=0
    CARGO_ARGS=--release
    EDP_ARGS=
fi

# for unit tests; it may not appply, as it'll be signed by runner's dummy key
export MRSIGNER="0000000000000000000000000000000000000000000000000000000000000000"
export TQE_MRENCLAVE="0000000000000000000000000000000000000000000000000000000000000000"
export TDBE_MRENCLAVE="0000000000000000000000000000000000000000000000000000000000000000"

# Add a test runner
mkdir .cargo
echo "[target.x86_64-fortanix-unknown-sgx]
runner = \"ftxsgx-runner-cargo\"" >> .cargo/config
cargo test --target x86_64-fortanix-unknown-sgx -p enclave-utils -p mls -p tx-validation-next