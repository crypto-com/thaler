#!/bin/bash
FILE=/usr/local/bin/kcov
if [ ! -f "$FILE" ]; then
    echo "$FILE does not exist"
    wget https://github.com/SimonKagstrom/kcov/archive/master.tar.gz
    tar xzf master.tar.gz
    cd kcov-master
    mkdir build
    cd build
    cmake ..
    make
    sudo make install
    cd ../..
    rm -rf kcov-master
fi
