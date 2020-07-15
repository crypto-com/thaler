#!/bin/bash
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

if [ -f $SGX_SDK/environment ]; then
    source $SGX_SDK/environment
fi

BUILD_PROFILE=${BUILD_PROFILE:-debug}
BUILD_MODE=${BUILD_MODE:-sgx}
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

cd ..
echo "Build $BUILD_MODE $BUILD_PROFILE"
if [ $BUILD_MODE == "sgx" ]; then
    # fix the rust-lld error: contains a compressed section, but zlib is not available
    export CFLAGS="-gz=none"

    cargo build $CARGO_ARGS
    cargo build $CARGO_ARGS --features mock-hardware-wallet --manifest-path client-cli/Cargo.toml
    make -C chain-tx-enclave/tx-validation

    # Add fortanix target and tools
    rustup target add x86_64-fortanix-unknown-sgx
    cargo install fortanix-sgx-tools sgxs-tools

    # FIXME: test enclave packages
    # LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm /opt/intel/sgx-aesm-service/aesm/aesm_service --no-daemon &
    # NETWORK_ID="ab" cargo test --target=x86_64-fortanix-unknown-sgx -p tx-validation-next -p enclave-utils

    # mls enclave -- FIXME: TDBE, mls should only be a library
    cargo build --target=x86_64-fortanix-unknown-sgx -p mls
    ftxsgx-elf2sgxs $EDP_TARGET_DIR/mls \
        --stack-size 0x40000 --heap-size 0x20000000 --threads 1 $EDP_ARGS
    sgxs-sign --key chain-tx-enclave/tx-validation/enclave/Enclave_private.pem $EDP_TARGET_DIR/mls.sgxs $EDP_TARGET_DIR/mls.sig \
        -d --xfrm 7/0 --isvprodid 0 --isvsvn 0

    # tx-query enclave
    cargo build --package tx-query2-app-runner
    RUSTFLAGS="-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3,+pclmul,+sha" cargo build --target x86_64-fortanix-unknown-sgx --package tx-query2-enclave-app
    ftxsgx-elf2sgxs $EDP_TARGET_DIR/tx-query2-enclave-app --heap-size 0x2000000 --stack-size 0x80000 --threads 6 $EDP_ARGS
    sgxs-sign --key chain-tx-enclave/tx-validation/enclave/Enclave_private.pem $EDP_TARGET_DIR/tx-query2-enclave-app.sgxs $EDP_TARGET_DIR/tx-query2-enclave-app.sig -d --xfrm 7/0 --isvprodid 0 --isvsvn 0

else
    cargo build $CARGO_ARGS --features mock-enclave --manifest-path client-rpc/server/Cargo.toml
    cargo build $CARGO_ARGS --features mock-enclave,mock-hardware-wallet --manifest-path client-cli/Cargo.toml
    cargo build $CARGO_ARGS --features mock-enclave --manifest-path dev-utils/Cargo.toml
    cargo build $CARGO_ARGS --features mock-enclave --manifest-path chain-abci/Cargo.toml
    cargo build $CARGO_ARGS -p ra-sp-server
fi

echo "Build dynamic cro-clib"
sed -i.bak -E "s/crate-type = \[\".+\"\]/crate-type = \[\"cdylib\"\]/" cro-clib/Cargo.toml
if [ $BUILD_MODE == "sgx" ]; then
    cargo build $CARGO_ARGS -p cro-clib
else
    cargo build $CARGO_ARGS --features mock-enclave --manifest-path cro-clib/Cargo.toml
fi
sed -i.bak -E "s/crate-type = \[\".+\"\]/crate-type = \[\"staticlib\"\]/" cro-clib/Cargo.toml
rm cro-clib/Cargo.toml.bak
