#!/bin/bash
cd /root/bin
echo "clear folders"
rm -rf /root/bin/.enclave
rm -rf /root/bin/.cro-storage
rm -rf /root/bin/.storage
rm -rf /enclave-storage
echo "copy binaries"
mkdir /root/bin
echo "copy tendermint config"
cp -Rf /root/disk/bin/* /root/bin
mkdir /root/.tendermint
mkdir /root/.tendermint/config
cp /root/config/*  /root/.tendermint/config
echo "clear disk"
/root/bin/tendermint unsafe_reset_all
sleep 2 
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
echo "ready"

cd /root/disk
/root/disk/launch.sh
sleep infinity
