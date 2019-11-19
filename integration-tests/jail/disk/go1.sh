#!/bin/bash
service ssh start
cd /root/disk
mkdir /root/chain
cp -Rf /root/chain_src/* /root/chain
cp ./config1/* /root/.tendermint/config
source ./go_common.sh
echo "OK"
echo "launch"
/root/disk/launch.sh
sleep infinity
