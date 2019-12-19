#!/bin/bash
echo "setup"
sleep 1

export CURRENT_HASH=$(git rev-parse HEAD)
echo "setup CURRENT_HASH=" $CURRENT_HASH

echo PATH=$PWD/disk/bin:$PATH
export PATH=$(pwd)/disk/bin:$PATH 
nix-shell ./jail.nix  --run "export PASSPHRASE=1 && python3 ../bot/make.py"
mkdir ./disk/config0
cp ./node0/tendermint/config/* ./disk/config0/

mkdir ./disk/config1
cp ./node1/tendermint/config/* ./disk/config1/

# nix
nix-shell ./jail.nix  --run "export PASSPHRASE=1 && python3 ../bot/open_port.py"
