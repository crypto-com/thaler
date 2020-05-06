# Note: This script should not be used for building enclave for production (it uses dummy signature which is not suitable for production).
set -e

APP_NAME=tx-query2-enclave-app
APP_PATH=chain-tx-enclave/tx-query-next/enclave-app
RUNNER_PATH=chain-tx-enclave/tx-query-next/app-runner
SP_PATH=chain-tx-enclave/enclave-ra/ra-sp-server

# Build runner
cd $RUNNER_PATH
cargo build
cd -

# Build enclave app
cd $APP_PATH
cargo build
cd -

# Convert the app
ftxsgx-elf2sgxs target/x86_64-fortanix-unknown-sgx/debug/$APP_NAME --heap-size 0x2000000 --stack-size 0x20000 --threads 6 --debug
