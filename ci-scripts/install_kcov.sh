#!/usr/bin/env bash

CARGO_KCOV_FILE="${HOME}/.cargo/bin/cargo-kcov"
KCOV_FILE="${HOME}/bin/kcov"
if [ ! -f "${CARGO_KCOV_FILE}" ] || [ ! -f "${KCOV_FILE}" ]; then
    echo "kcov is not installed"
    wget https://github.com/SimonKagstrom/kcov/archive/master.tar.gz
    tar xzf master.tar.gz
    cd kcov-master
    mkdir build
    cd build
    cmake ..
    make
    sudo make install
    sudo mv /usr/local/bin/kcov "${HOME}/bin"
    sudo mv /usr/local/bin/kcov-system-daemon "${HOME}/bin"
    cd ../..
    rm -rf kcov-master
fi
