#!/bin/bash
service ssh start
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
cargo build
cd /root/chain/chain-tx-enclave/tx-validation
make
cd /root
cp /root/chain/target/debug/client-rpc /root/bin
cp /root/chain/target/debug/client-cli /root/bin
cp /root/chain/target/debug/chain-abci /root/bin
cp /root/chain/target/debug/dev-utils /root/bin
cp /root/chain/chain-tx-enclave/tx-validation/bin/enclave.signed.so /root/bin
cp /root/chain/chain-tx-enclave/tx-validation/bin/tx-validation-app /root/bin
echo "copied"
cd /root/bin
rm -rf /root/bin/.enclave
rm -rf /root/bin/.cro-storage
rm -rf /root/bin/.storage
rm -rf /enclave-storage
sleep 1
echo "clear folders"
ls /root/bin -la
/root/bin/tendermint unsafe_reset_all
/root/disk/launch.sh
echo "ready"
sleep 10 
#python3 /root/disk/test.py
sleep infinity 
