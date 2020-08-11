# "next" tx-query (WIP)
work in progress implementation as per
https://github.com/crypto-com/chain/blob/master/architecture-docs/adr-002.md

## Instructions
Install EDP: https://edp.fortanix.com/docs/installation/guide/
(Note: Linux-only)

build runner:
```
cd app-runner
cargo +nighly build
cd ..

build and (debug) sign enclave :
```
cd enclave-app
cargo +nightly build --target=x86_64-fortanix-unknown-sgx
cd ../../../target/x86_64-fortanix-unknown-sgx/debug
ftxsgx-elf2sgxs tx-query2-enclave-app --heap-size 0x20000 --stack-size 0x20000 --threads 6 --debug
sgxs-sign --key <KEY> tx-query2-enclave-app.sgxs tx-query2-enclave-app.sig -d --xfrm 7/0 --isvprodid 0 --isvsvn 0
```
