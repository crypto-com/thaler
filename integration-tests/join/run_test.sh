#!/bin/bash
echo "run test"

. ./run_open_port.sh
. ./run_test_env.sh

echo "client rpc port="$JAIL_CLIENT_RPC
echo "chain rpc port="$JAIL_CHAIN_RPC


export CURRENT_HASH=$(git rev-parse HEAD)
echo "run CURRENT_HASH=" $CURRENT_HASH
docker-compose -p $CURRENT_HASH up -d  
echo "docker compose ok"
nix-shell ../jail/jail.nix  --run "export PASSPHRASE=1 && python3 ../bot/join_test.py"
ret=$?
if [ $ret -ne 0 ]; then
    exit -1
fi
docker-compose -p $CURRENT_HASH down
