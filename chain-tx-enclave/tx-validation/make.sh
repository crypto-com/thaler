#!/bin/bash
set -e

source /root/.docker_bashrc
cd ./chain-tx-enclave/tx-validation
make clean
make
