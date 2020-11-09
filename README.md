# DEVELOPMENT OF CRYPTO.COM CHAIN MOVED TO: https://github.com/crypto-com/chain-main

## Table of Contents

1. [Description](#description)
2. [Contributing](#contributing)
3. [License](#license)
4. [Documentation](#documentation)
5. [Build](#build)
   1. [Docker image](#docker-image)
   2. [Makefile](#makefile)
   3. [Linux native (Ubuntu 18.04)](#linux-native)
   4. [Build mock mode on non-sgx platform (e.g. mac)](#build-mock-mode)
6. [Start a Local Full Node](#start-local-full-node)
7. [Send your First Transaction](#send-first-transaction)
8. [Testing](#testing)
9. [Useful Links](#useful-links)

<a id="description" />

## 1. Description

This repository contains the Thaler Experimental Network code (pre-pivoted Crypto.com Chain). The current repository consists of the following Rust sub-crates:

* *chain-abci*: the Tendermint ABCI application that currently does the transaction validation etc.
* *chain-core*: the library that contains the main type definitions and any utility code (such as serialization), so that it can be used in *chain-abci* and other applications.
* *chain-storage*: storage related logic used by *chain-abci*.
* *chain-tx-filtering*: Library that captures the fuctionality related to block-level public view key-based transaction filtering.
* *chain-tx-validation*: Library with functions that verify, given current chain state's data, if a transaction is valid.
* *test-common*: Common code shared by unit tests.
* *dev-utils*: currently a minimal development tool for generating genesis.json
* *client-[common|network|core|cli|rpc]*: Client backend implementation for transaction creation and wallet management. Follow
these links for more details:
  - [client-common](./client-common/README.md)
  - [client-core](./client-core/README.md)
  - [client-rpc](./client-rpc/README.md)
* *chain-tx-enclave/*: enclaves and enclave wrapper apps.
* *enclave-protocol*: Requests and responses exchanges over ZMQ between chain-abci app.
* *cro-clib*: c API library.

<a id="contributing" />

## 2. Contributing
Please abide by the [Code of Conduct](CODE_OF_CONDUCT.md) in all interactions,
and the [contributing guidelines](CONTRIBUTING.md) when submitting code.

<a id="license" />

## 3. License

[Apache 2.0](./LICENSE)

<a id="documentation" />

## 4. Documentation

Technical documentation can be found in this [Github repository](https://github.com/crypto-com/thaler-docs) (you can read it in [this hosted version](https://thaler-testnet.crypto.com/docs/getting-started/).

<a id="build" />

## 5. Build full node

<a id="docker-image" />

#### 1. Docker image

```bash
$ docker build -t crypto-chain:latest .
```

Docker build arguments:

- `SGX_MODE`:
  - `HW`: SGX hardware mode, *default*.
  - `SW`: SGX software simulation mode.
- `NETWORK_ID`: Network HEX Id of Tendermint, *default*: `AB`.
- `BUILD_PROFILE`:
  - `debug`: debug mode.
  - `release`: release mode, *default*.
- `BUILD_MODE`:
  - `sgx`: *default*.
  - `mock`: A simulation mode only for development on non-sgx platform, don't use in production.

<a id="makefile" /> 

#### 2. Makefile

```bash
$ make build
```

It builds in docker container, the result binaries reside in local directory, it runs something like:

```bash
$ docker run --rm -v `pwd`:/chain cryptocom/chain:latest run_build_scripts
```

> The result binary is built for the docker container environment, may not runnable locally.

The makefile supports other commands too:

```bash
$ make help
...
SUBCOMMAND:
	prepare                prepare the environment
	image                  build the docker image
	build                  just build the chain and enclave binaery in docker
	run-sgx                docker run sgx-validation and a sgx-query container
	run-chain              docker run chain-abci, tendermint and client-rpc container
	stop-all               docker stop all the container
	start-all              docker start all the container
	restart-all            docker restart all the container
	rm-all                 remove all the docker container
	clean                  clean all the temporary files while compiling
	clean-data             remove all the data in data_path
```

<a id="linux-native" />

#### 3. Linux native (Ubuntu 18.04)

Prerequisite:

- [intel sgx sdk](https://software.intel.com/en-us/sgx/sdk) (Set environment variable `SGX_SDK` to the sdk directory)
- rust toolchain nightly-2019-11-25 (you can install with [rustup](https://rustup.rs/))

```bash
$ apt-get install -y \
    cmake \
    libgflags-dev \
    libzmq3-dev \
    pkg-config \
    clang
$ ./docker/build.sh
```

All the executables and signed enclave libraries will reside in `./target/debug`.

Environment variables mentioned in the [docker image building section](#docker-image) also apply here.

<a id="build-mock-mode" />

#### 4. Develop with mock mode on non-sgx platform (e.g. mac)

TODO

<a id="start-local-full-node" />

## 6. Start a Local Full Node

Please follow the [instruction](https://thaler-testnet.crypto.com/docs/getting-started/local-devnet.html) to deploy a local full node.

<a id="send-first-transaction" />

## 7. Send Your First Transaction

Kindly refer to this [instruction](https://thaler-testnet.crypto.com/docs/getting-started/local-devnet.html#send-your-first-transaction) to perform transactions between addresses.

<a id="testing" />

## 8. Testing

You can run the unit tests and integration tests with [drone-cli](https://docs.drone.io/cli/install/) on sgx platform:

```bash
$ cat > .drone.secret << EOF
SPID=<SPID>
IAS_API_KEY=<IAS_API_KEY>
EOF
$ drone exec --trusted \
    --include build \
    --include unit-tests \
    --include integration-tests \
    --include multinode-tests
```

Kindly refer to [Prepare SPID & KEY](https://thaler-testnet.crypto.com/docs/getting-started/local-devnet.html#prepare-spid-key) to obtain the values of `SPID` and `IAS_API_KEY`. 

---

<a id="useful-links" />

## 9. Useful links

* [Project Website](https://thaler-testnet.crypto.com/)
* [Technical Documentation](https://thaler-testnet.crypto.com/docs/)
* Community chatrooms (non-technical): [Discord](https://discord.gg/nsp9JTC) [Telegram](https://t.me/CryptoComOfficial)
* Developer community chatroom (technical): [![Gitter](https://badges.gitter.im/crypto-com/community.svg)](https://gitter.im/crypto-com/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
