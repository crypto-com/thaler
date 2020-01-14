#!/bin/bash
export RUST_LOG=info
cd /root/bin 

echo "activate aesm"
./aesm.sh 
sleep 2 

echo "activate enclave"
nohup ./enclave.sh  > enclave.log &
sleep 2 

echo "activate query"
cd ./query
nohup ./query.sh  > query.log &
cd .. 
sleep 2 


echo "activate abci"
nohup ./abci.sh  > abci.log &
sleep 2 

echo "activate tendermint"
./tendermint.sh  &
sleep 20 

echo "activate client-rpc"
nohup ./client-rpc.sh > rpc.log & 
sleep 1

