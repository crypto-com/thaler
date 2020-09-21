#!/usr/bin/env bash

pushd "${HOME}"
if [ ! -f "bin/protoc" ]; then
    PROTOBUF_VERSION=3.3.0
    PROTOC_FILENAME=protoc-${PROTOBUF_VERSION}-linux-x86_64.zip
    wget https://github.com/google/protobuf/releases/download/v${PROTOBUF_VERSION}/${PROTOC_FILENAME}
    unzip ${PROTOC_FILENAME}
    bin/protoc --version
    popd
fi