#!/bin/bash
set -e

source /root/.docker_bashrc

export SGX_MODE=HW
export NETWORK_ID=ab
export RUST_LOG=debug
export RUST_BACKTRACE=1
export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3
export TX_VALIDATION_BIN_DIR=$PWD/chain-tx-enclave/tx-validation/bin/
export TX_QUERY_APP_PORT=`ci-scripts/find-free-port.sh`

ls /dev/sgx
# aesm assumed to be passed in
ls /var/run/aesmd/aesm.socket

# LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service &

# echo "[aesm_service] Running in background ..."
# # Wait for aesm_service to initialize
# sleep 1


cd chain-tx-enclave/tx-validation
make clean
make

export SGX_TEST=1
cd ../tx-query
make clean
make

cd bin
# assumes SPID + IAS_API_KEY environment variables are set from outside / docker
./tx-query-app