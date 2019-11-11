#!/bin/bash
export SGX_MODE=SW
export NETWORK_ID=ab
export RUSTFLAGS=-Ctarget-feature=+aes,+ssse3
export PATH=$HOME/.cargo/bin:$HOME/bin:$PATH
export APP_PORT=25933
export TX_ENCLAVE_STORAGE=/enclave-storage
export LD_LIBRARY_PATH=$HOME/lib
export PKG_CONFIG_PATH=$HOME/lib/pkgconfig
source ~/.bashrc
