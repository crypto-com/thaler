#!/bin/bash
cat /etc/issue
sed -i 's/archive.ubuntu.com/ftp.daum.net/g' /etc/apt/sources.list
rm -rf /var/lib/apt/lists/*
apt update
apt install wget curl -y
apt install python3 libssl-dev libcurl4-openssl-dev libelf-dev libdw-dev  gcc binutils-dev libc6-dev -y
apt install pkg-config -y

apt install build-essential -y

wget http://www.cmake.org/files/v3.2/cmake-3.2.2.tar.gz
tar xf cmake-3.2.2.tar.gz
cd cmake-3.2.2
./configure
make
make install
cd ..


curl https://sh.rustup.rs -sSf | sh -s -- -y
cmake --version
echo "prepare OK"
