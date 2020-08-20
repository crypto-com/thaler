#!/bin/bash
set -xe
cd chain-abci
## build fuzzer
cargo install cargo-fuzz
# dummy values
export NETWORK_ID="ab"
export MRSIGNER="0000000000000000000000000000000000000000000000000000000000000000"
export TQE_MRENCLAVE="0000000000000000000000000000000000000000000000000000000000000000"
cargo fuzz run abci-cycle -- -runs=0
wget -q -O fuzzit https://github.com/fuzzitdev/fuzzit/releases/download/v2.4.77/fuzzit_Linux_x86_64
chmod a+x fuzzit
./fuzzit create job --type fuzzing abci-cycle ./fuzz/target/x86_64-unknown-linux-gnu/release/abci-cycle