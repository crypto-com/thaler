#!/usr/bin/env bash

wget https://download.01.org/intel-sgx/sgx-linux/2.8/distro/ubuntu16.04-server/sgx_linux_x64_sdk_2.8.100.3.bin
chmod +x sgx_linux_x64_sdk_2.8.100.3.bin
echo -e 'no\n/opt' | ./sgx_linux_x64_sdk_2.8.100.3.bin
