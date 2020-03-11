#!/bin/bash
URL=git@github.com:crypto-com/sample-chain-ios-example.git
FOLDER=./examples/sample-chain-ios-example
if [ ! -d "$FOLDER" ] ; then
    git clone "$URL" "$FOLDER"
fi
