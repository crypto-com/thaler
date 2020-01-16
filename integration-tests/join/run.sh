#!/bin/bash
echo "join test"

source /etc/profile.d/nix.sh
. ./run_compile.sh

export PATH=$(pwd)/disk/bin:$PATH
echo "binaries"
echo $PATH
ls $(pwd)/disk/bin

echo "setup"
sleep 2
#setup
. ./run_setup.sh

#open port
echo "open port"
. ./run_open_port.sh
sleep 1

echo "preparing test"
sleep 5
# test
. ./run_test.sh

echo "test finished successfully"
exit 0
