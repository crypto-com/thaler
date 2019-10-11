#!/bin/bash
FILE=/home/travis/lib/libzmq.so
if [ ! -f "$FILE" ]; then
    echo "$FILE does not exist"
    wget https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz
    tar xvfz libsodium-1.0.16.tar.gz
    cd libsodium-1.0.16
    ./configure --prefix=$HOME
    make
    make install
    cd ..

    wget https://github.com/zeromq/libzmq/releases/download/v4.2.5/zeromq-4.2.5.tar.gz
    tar xvfz zeromq-4.2.5.tar.gz
    cd zeromq-4.2.5
    ./configure --prefix=$HOME --with-libsodium
    make
    make install
    cd ..
fi
