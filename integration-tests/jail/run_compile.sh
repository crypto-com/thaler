#!/bin/bash
echo "compile binaries"
SRC=../../target/debug
FILE=./disk/bin
export CURRENT_HASH=$(git rev-parse HEAD)

echo "compile enclave"
if [ -f "$FILE/tx-validation-app" ] && [ -f "$FILE/query/tx-query-app" ]
then
	echo "sgx binaries ready"
else
	cd ./compile
	echo "compile CURRENT_HASH=" $CURRENT_HASH
	docker-compose -p $CURRENT_HASH up
	cd ..
fi



if [ -f "$FILE/client-rpc" ] && [ -f "$FILE/client-cli" ] && [ -f "$FILE/chain-abci" ] && [ -f "$FILE/dev-utils" ]
then
	echo "binaries ready"
else
	echo "compile chain"
	nix-shell rust.nix --run "cargo build"
	cp $SRC/client-rpc  $FILE/client-rpc
	cp $SRC/client-cli  $FILE/client-cli
	cp $SRC/chain-abci  $FILE/chain-abci
	cp $SRC/dev-utils  $FILE/dev-utils
fi



echo "check binaries"
if [ -f "$FILE/client-rpc" ] && [ -f "$FILE/client-cli" ] && [ -f "$FILE/chain-abci" ] && [ -f "$FILE/dev-utils" ]&& [ -f "$FILE/tx-validation-app" ] && [ -f "$FILE/query/tx-query-app" ]

then
	echo "compile scuccesss"
else
	echo "compile failed"	
	exit -1
fi

