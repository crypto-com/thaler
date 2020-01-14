#!/bin/bash
echo "compile binaries"

SRC=../jail/disk/bin
FILE=./disk/bin
mkdir $FILE
cp -Rf $SRC/* $FILE

echo "check binaries"
if [ -f "$FILE/client-rpc" ] && [ -f "$FILE/client-cli" ] && [ -f "$FILE/chain-abci" ] && [ -f "$FILE/dev-utils" ]&& [ -f "$FILE/tx-validation-app" ] && [ -f "$FILE/query/tx-query-app" ]

then
	echo "compile scuccesss"
else
	echo "compile failed"	
	exit -1
fi

