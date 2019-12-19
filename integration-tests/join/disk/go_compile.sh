#!/bin/bash
cd /root/disk
mkdir /root/chain
cp -Rf /root/chain_src/* /root/chain
source /root/disk/prepare.sh
source /opt/sgxsdk/environment
source /root/.cargo/env
echo "sgx mode=" $SGX_MODE
echo "network id=" $NETWORK_ID
echo "path=" $PATH 
echo "enclave storage=" $TX_ENCLAVE_STORAGE
echo "rust flags=" $RUSTFLAGS
echo "app port=" $APP_PORT
echo "compile chain"
pwd
ls
cd /root/chain
cargo clean
cargo build
cd /root/chain/chain-tx-enclave/tx-validation
make clean
make
cd /root
cp /root/chain/target/debug/client-rpc /root/disk/bin
cp /root/chain/target/debug/client-cli /root/disk/bin
cp /root/chain/target/debug/chain-abci /root/disk/bin
cp /root/chain/target/debug/dev-utils /root/disk/bin
cp /root/chain/chain-tx-enclave/tx-validation/bin/enclave.signed.so /root/disk/bin
cp /root/chain/chain-tx-enclave/tx-validation/bin/tx-validation-app /root/disk/bin
cp /root/bin/tendermint /root/disk/bin
echo "copied OK"
