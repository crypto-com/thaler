<p align="center">
  <img src="https://avatars0.githubusercontent.com/u/41934032?s=400&v=4" alt="Crypto.com Chain" width="400">
</p>

<h1 align="center"><a href="https://crypto.com">Crypto.com<a> Chain</h1>

<p align="center">
  <a href="https://travis-ci.org/crypto-com/chain"><img label="Build Status" src="https://travis-ci.org/crypto-com/chain.svg?branch=master" /></a>
  <a href="https://codecov.io/gh/crypto-com/chain"><img label="Code Coverage" src="https://codecov.io/gh/crypto-com/chain/branch/master/graph/badge.svg" /></a>
  <a href="https://gitter.im/crypto-com/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge"><img label="Gitter" src="https://badges.gitter.im/crypto-com/community.svg" /></a>
</p>

## Table of Contents

1. [Description](#description)
2. [Contributing](#contributing)
3. [License](#license)
4. [Documentation](#documentation)<br />
5. [Building](#building)<br />
  5.1. [Build Prerequisites](#build-prerequisites)<br />
  5.2. [Build from Source Code](#build-from-src)<br />
6. [Start a Local Full Node](#start-local-full-node)<br />
7. [Send your First Transaction](#send-first-transaction)
8. [Testing](#testing)
9. [Useful LInks](#useful-links)
 
<a id="description" />

## 1. Description

This repository contains the pre-alpha version prototype implementation of Crypto.com Chain. The current repository consists of the following Rust sub-crates:

* *chain-abci*: the Tendermint ABCI application that currently does the transaction validation etc.

* *chain-core*: the library that contains the main type definitions and any utility code (such as serialization), so that it can be used in *chain-abci* and other applications.

* *dev-utils*: currently a minimal development tool for generating genesis.json

* *client-[common|index|core|rpc]*: Client backend implementation for transaction creation and wallet management. Follow
these links for more details:
  - [client-common](./client-common/README.md)
  - [client-core](./client-core/README.md)
  - [client-rpc](./client-rpc/README.md)

<a id="contributing" />

## 2. Contributing
Please abide by the [Code of Conduct](CODE_OF_CONDUCT.md) in all interactions,
and the [contributing guidelines](CONTRIBUTING.md) when submitting code.

<a id="license" />

## 3. License

[Apache 2.0](./LICENSE)

<a id="building" />

## 4. Documentation

Technical documentation can be found in this [Github repository](https://github.com/crypto-com/chain-docs) (you can read it in [this hosted version](https://crypto-com.github.io)).

<a id="documentation" />

## 5. Build

<a id="build-prerequisites" />

### 5.1. Build Prerequisites

Crypto.com chain requires the following to be installed before build.
- [Homebrew](https://brew.sh/)
- [Tendermint](https://tendermint.com/docs/introduction/install.html#from-binary)
- [Rust and Cargo](https://rustup.rs) (cargo version: 1.36 onwards)
- [cmake](https://cmake.org/install/)
  ```bash
  $ brew install cmake
  ```
- [ZeroMQ](https://zeromq.org/download/)
  ```bash
  $ brew install zmq
  ```
- pkg-config
  ```bash
  $ brew install pkg-config
  ```

After all dependencies are installed, add the following lines to `~/.cargo/config` to enable generating instructions for Streaming SIMD Extensions 3 and Advanced Vector Extensions on build:
```
[build]
rustflags = ["-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"]
```

(TODO: In the future, the build tooling may be migrated to Bazel / Nix etc. for reproducible builds.)

<a id="build-instructions" />

### 5.2. Build Instructions
```bash
$ git clone git@github.com:crypto-com/chain.git
$ cd chain

$ cargo build
```
The built executables will be put inside folder `/target/debug/` by default.

<a id="start-local-full-node" />

## 6. Start a Local Full Node

Please follow the [instruction](https://crypto-com.github.io/getting-started/local_full_node_development.html) to deploy a local full node.



<a id="send-first-transaction" />

## 7. Send Your First Transaction

Kindly refer to this [instruction](https://crypto-com.github.io/getting-started/send_your_first_transaction.html#send-your-first-transaction) to perform transactions between addresses.

<a id="testing" />

## 8. Testing

To run the test cases
```bash
$ cargo test
```

To measure code coverage by [cargo-tarpaulin](https://crates.io/crates/cargo-tarpaulin):
```bash
$ cargo tarpaulin
```

This only works on x86_64 processors running Linux. On different platforms, you will need to use [Docker](https://docs.docker.com/install/):

```bash
$ docker run --security-opt seccomp=unconfined -v "$PWD:/volume" xd009642/tarpaulin
```

---

<a id="useful-links" />

## 9. Useful links

* [Project Website](http://crypto.com/chain)
* [Technical Documentation](https://crypto-com.github.io)
* Community chatrooms (non-technical): [Discord](https://discord.gg/nsp9JTC) [Telegram](https://t.me/CryptoComOfficial)
* Developer community chatroom (technical): [![Gitter](https://badges.gitter.im/crypto-com/community.svg)](https://gitter.im/crypto-com/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
