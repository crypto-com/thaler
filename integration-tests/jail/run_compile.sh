#!/bin/bash
echo "compile binaries"

echo "compile enclave"
cd ./compile
export CURRENT_HASH=$(git rev-parse HEAD)
echo "compile CURRENT_HASH=" $CURRENT_HASH
docker-compose -p $CURRENT_HASH up
cd ..

echo "compile chain"
nix-shell rust.nix --run "cargo build"
SRC=../../target/debug
FILE=./disk/bin

cp $SRC/client-rpc  $FILE/client-rpc
cp $SRC/client-cli  $FILE/client-cli
cp $SRC/chain-abci  $FILE/chain-abci
cp $SRC/dev-utils  $FILE/dev-utils



echo "check binaries"
if [ -f "$FILE/client-rpc" ] && [ -f "$FILE/client-cli" ] && [ -f "$FILE/chain-abci" ] && [ -f "$FILE/dev-utils" ]&& [ -f "$FILE/tx-validation-app" ]
then
	echo "compile scuccesss"
else
	echo "compile failed"	
	exit -1
fi

