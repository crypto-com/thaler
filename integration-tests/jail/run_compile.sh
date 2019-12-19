#!/bin/bash
echo "compile binaries"
cd ./compile


export CURRENT_HASH=$(git rev-parse HEAD)
echo "compile CURRENT_HASH=" $CURRENT_HASH
docker-compose -p $CURRENT_HASH up
cd ..


FILE=./disk/bin
if [ -f "$FILE/client-rpc" ] && [ -f "$FILE/client-cli" ] && [ -f "$FILE/chain-abci" ] && [ -f "$FILE/dev-utils" ]&& [ -f "$FILE/tx-validation-app" ]
then
	echo "compile scuccesss"
else
	echo "compile failed"	
	exit -1
fi

