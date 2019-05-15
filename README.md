<p align="center">
  <img src="https://avatars0.githubusercontent.com/u/41934032?s=400&v=4" alt="Crypto.com Chain" width="400">
</p>

# Crypto.com Chain
[![Build Status](https://travis-ci.org/crypto-com/chain.svg?branch=master)](https://travis-ci.org/crypto-com/chain)
[![codecov](https://codecov.io/gh/crypto-com/chain/branch/master/graph/badge.svg)](https://codecov.io/gh/crypto-com/chain)
[![Gitter](https://badges.gitter.im/crypto-com/community.svg)](https://gitter.im/crypto-com/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

This repository contains the pre-alpha version prototype implementation of Crypto.com Chain. The current repository consists of the following Rust sub-crates:

* *chain-abci*: the Tendermint ABCI application that currently does the transaction validation etc.

* *chain-core*: the library that contains the main type definitions and any utility code (such as serialization), so that it can be used in *chain-abci* and other applications.

* *dev-utils*: currently a minimal development tool for generating genesis.json

* *signer-[cli|core|rpc]*: work-in-progress infrastructure for client code, such as wallet implementations and third party integrations.

* *client-[common|index|core|rpc]*: Client backend implementation for transaction creation and wallet management. Follow
these links for more details:
  - [client-common](./client-common/README.md)
  - [client-index](./client-index/README.md)
  - [client-core](./client-core/README.md)
  - [client-rpc](./client-rpc/README.md)

## Contributing
Please abide by the [Code of Conduct](CODE_OF_CONDUCT.md) in all interactions,
and the [contributing guidelines](CONTRIBUTING.md) when submitting code.

## License

[Apache 2.0](./LICENSE)

## Prerequisites 

Tendermint: https://github.com/tendermint/tendermint/releases

Rust tooling (cargo + cmake): https://rustup.rs

(TODO: In the future, the build tooling may be migrated to Bazel / Nix etc. for reproducible builds.)

## How to build it
Before building, add the following lines to `~/.cargo/config`
```
[build]
rustflags = ["-Ctarget-feature=+aes,+ssse3"]
```

Then build the executables
```
$ cargo build
```
The built executables will be put inside folder `/target/debug/` by default.

## How to run the test suite
```
$ cargo test
```

To measure code coverage, one can run
```
$ cargo tarpaulin
```

This only works on x86_64 processors running Linux. On different platforms, 

```
$ docker run --security-opt seccomp=unconfined -v "$PWD:/volume" xd009642/tarpaulin
```

## How to run a full node
1. generate address -- currently, there is a signer cli for this purpose (TODO / NOTE: signer-cli is going to be deprecated in favor of client-client )
```
$ signer-cli -- address generate --name <NAME>
```
This command will create an address with name <NAME>. After entering the passphase, the address is generated.
```
$ signer-cli -- address get -n <NAME>

Enter passphrase:
Spend address: <ETH_ADDRESS_HEX_BYTES>
View address: <VIEW_ETH_ADDRESS_HEX_BYTES>
```

2. generate initial state -- currently, a very naive way is in dev-utils. The `chain_id` will be used in Tendermint configuration later. At this point, just use two hex digits.

2a. prepare a "mapping" / snapshot file (each line contains the address and the amount):
```
0x<ETH_ADDRESS_HEX_BYTES_1> <AMOUNT_1>
0x<ETH_ADDRES_HEX_BYTES_2> <AMOUNT_2>
...
```

Note that the sum of amounts needs to equal to the total supply in base units.

2b. run the dev-utils command:

```
$ dev-utils -- genesis generate --base_fee <x.xxxx> --chain-id <CHAIN_ID> --launch_incentive_from <SOME_ETH_ADDRESS_HEX_BYTES> --launch_incentive_to <SOME_ETH_ADDRESS_HEX_BYTES> --long_term_incentive <SOME_ETH_ADDRESS_HEX_BYTES> --mapping_file_path <PATH_TO_MAPPING_FILE> --per_byte_fee <x.xxxx>
```

Note that launch_incentive_from, launch_incentive_to and long_term_incentive need to be present in the mapping file (their amounts will be put in the initial rewards pool).

In the end, you should get two pieces of data:
```
"app_hash": "<APP_HASH_HEX_BYTES>",
"app_state": {"distribution":{"0x<ETH_ADDRESS_HEX_BYTES_1>":<AMOUNT_1>,...},"launch_incentive_from":"<SOME_ETH_ADDRESS_HEX_BYTES>","launch_incentive_to":"<SOME_ETH_ADDRESS_HEX_BYTES>","long_term_incentive":"<SOME_ETH_ADDRESS_HEX_BYTES>","initial_fee_policy":{"constant":xxxx,"coefficient":xxxx}}
```

"app_hash" is the initial application hash -- currently, it's computed as a hash of the initial rewards pool state and a root of a merkle tree of initial transaction IDs.

3. initialize a Tendermint node:
```
$ tendermint init
```

If you previously initialized a Tendermint node, you may need to run before it:
```
$ tendermint unsafe_reset_all
```

4. configure a Tendermint node:

One thing to change would be the change `genesis.json` to have `app_hash` and `app_state` obtained in step 1. Also, make sure reusing the `chain_id` we come up earlier, which should ends with two hex digits (e.g. test-chain-mafL4t-AA).

5. run CRO ABCI process, e.g.:
```
$ chain-abci -g "<APP_HASH_HEX_BYTES>" -c <FULL_CHAIN_ID>
```
The string passed to `-g` is the genesis `app_hash` obtained in step 1 and configured in the previous step. The string passed to `-c` is the `full_chain_id` that ends with two hex digits (e.g. test-chain-mafL4t-AA).

If you need backtraces or logging, set the environment variables before it:
```
RUST_BACKTRACE=1 RUST_LOG=info 
```

6. run a Tendermint process:
in a different terminal:

```
$ tendermint node
```

## How to run a basic lite node
```
$ tendermint lite
```

## How to send TX, query, etc.

See Tendermint RPC documentation: https://tendermint.com/rpc/#introduction

Currently, there's a rough command-line application in `signer/app` for testing purposes.

Its workflow is the following:

1. Generate a new keypair: `signer address generate -n <NAME>` (you can view hex-encoded addresses of corresponding key with `signer address get -n <NAME>`)

2. Generate a signed TX with: 
```
$ signer-cli transaction generate -n <NAME> -c <CHAIN_ID>
```

Right now there is no concept of fee, you must spend the whole input in the output(s).

After entering all the required data, this will print out a hex-encoded TXID (blake2s hash) and a hex-encoded RLP-serialized TX structure / content. You can decode it and transform it as necessary, e.g. into base64.

3. You can then send a TX using the `broadcast_tx` Tendermint RPC command (e.g. JSONRPC over HTTP or websockets). 
For example, for the [URI/HTTP option](https://tendermint.com/rpc/#uri-http), it can look like this:

```
http://localhost:26657/broadcast_tx_sync?tx=0xa200a30081a200982018f318bc1844182918821848188a18a51835186118f51877189c031868186618f8188a185b18cb185d18b418da18a518db18d6183f18e2185018f200184701000181a20082009418431835186b18fe18ec011858183d18fe1878187e183d181f18a3181918ae06189c181e189801185002a10018aa0181820183820298201861189718f318a518bb184918ea00187205187318ad18b6184318cd182a1841183518dc1825181a0b18ac181d184418f718a118c418680018f701829820188718d90c186d183518ee189218410f186c189118d418c418d518c5184e189a189418f7185d181a1820182b18b1181e18e618b51018e3184c1851186d982018220d18b71859183718af187018b818c8185f18731893188618e0181918e918fc18b5185718c3188c182b188b185e1882184618d7189d187218f4183d181980
```

## Useful links

* [Project Website](http://crypto.com/chain)
* Community chatrooms (non-technical): [Discord](https://discord.gg/nsp9JTC) [Telegram](https://t.me/CryptoComOfficial)
* Developer community chatroom (technical): [![Gitter](https://badges.gitter.im/crypto-com/community.svg)](https://gitter.im/crypto-com/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
