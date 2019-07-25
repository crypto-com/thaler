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
4. [Building](#building)<br />
  4.1. [Build Prerequisites](#build-prerequisites)<br />
  4.2. [Build from Source Code](#build-from-src)<br />
5. [Start a Local Full Node](#start-local-full-node)<br />
  5.1. [Create a Wallet](#create-wallet)<br />
  5.2. [Generate Genesis](#generate-genesis)<br />
  5.3. [Start Chain Transaction Enclaves](#start-chain-transaction-enclaves)<br />
  5.4. [Start Tendermint](#start-tendermint)<br />
  5.5. [Start Chain ABCI](#start-chain-abci)<br />
6. [Start a Basic Lite Node](#start-lite-node)<br />
7. [Send your First Transaction](#send-first-transaction)
8. [Testing](#testing)
8. [Useful LInks](#useful-links)
 
<a id="description" />

## 1. Description

This repository contains the pre-alpha version prototype implementation of Crypto.com Chain. The current repository consists of the following Rust sub-crates:

* *chain-abci*: the Tendermint ABCI application that currently does the transaction validation etc.

* *chain-core*: the library that contains the main type definitions and any utility code (such as serialization), so that it can be used in *chain-abci* and other applications.

* *dev-utils*: currently a minimal development tool for generating genesis.json

* *client-[common|index|core|rpc]*: Client backend implementation for transaction creation and wallet management. Follow
these links for more details:
  - [client-common](./client-common/README.md)
  - [client-index](./client-index/README.md)
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

## 4. Build

<a id="build-prerequisites" />

### 4.1. Build Prerequisites

Crypto.com chain requires the following to be installed before build.

- [Tendermint](https://github.com/tendermint/tendermint/releases)
- [Rust and Cargo](https://rustup.rs)
- cmake
  ```bash
  $ brew install cmake
  ```
- ZeroMQ
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
rustflags = ["-Ctarget-feature=+aes,+ssse3"]
```

(TODO: In the future, the build tooling may be migrated to Bazel / Nix etc. for reproducible builds.)

<a id="build-instructions" />

### 4.2. Build Instructions
```bash
$ git clone git@github.com:crypto-com/chain.git
$ cd chain

$ cargo build
```
The built executables will be put inside folder `/target/debug/` by default.

<a id="start-local-full-node" />

## 5. Start a Local Full Node

### 5.1. Initialize Tendermint

```bash
$ tendermint init
```

If you previously initialized a Tendermint node, you may need to run before it:
```bash
$ tendermint unsafe_reset_all
```
<a id="create-wallet" />

### 5.1. Create a Wallet

We will need a wallet to receive genesis funds.

To create a wallet, currently we have [client-rpc](https://github.com/crypto-com/chain/client-rpc) and [client-cli](https://github.com/crypto-com/chain/client-cli) available for this purpose. We will be using [client-cli](https://github.com/crypto-com/chain/client-cli) in this guide.

- Create a new wallet with name "Default". You will be prompted to enter a passphrase.
  ```bash
  $ ./target/debug/client-cli wallet new --name Default
  ```
- Generate an address for the wallet to receive genesis funds. You will be prompted to enter the wallet passphrase again
  ```bash
  $ ./target/debug/client-cli address new --name Default --type Staking
  Enter passphrase: 
  New address: 0x3a102b53a12334e984ef51fda0baab1768116363
  ```

<a id="generate-genesis" />

### 5.2. Generate Genesis

Genesis describes the initial funding distributions as well as other configurations such as validators setup. We will be distributing funds to our newly-created wallet address.

We will need the following information to generate a genesis:
- **Address to Receive Genesis Funds**: We have just created one in the last step
- **Genesis Time**: Copy the `genesis_time` from `~/.tendermint/config/genesis.json`
- **Validator Pub Key**: Copy the `pub_key.value` from `~/.tendermint/config/priv_validator_key.json`

Create a Genesis configuration file `dev-conf.json`
- Replace `{WALLET_ADDRESS}`, `{PUB_KEY}` and `{GENESIS_TIME}` with information obtained above.
```json
{
    "distribution": {
        "{WALLET_ADDRESS}": "2500000000000000000",
        "0x20a0bee429d6907e556205ef9d48ab6fe6a55531": "2500000000000000000",
        "0x35f517cab9a37bc31091c2f155d965af84e0bc85": "2500000000000000000",
        "0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de": "1250000000000000000",
        "0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07": "1250000000000000000"
    },
    "unbonding_period": 60,
    "required_council_node_stake": "1250000000000000000",
    "initial_fee_policy": {
        "base_fee": "1.1",
        "per_byte_fee": "1.25"
    },
    "council_nodes": [
        {
            "staking_account_address": "0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de",
            "consensus_pubkey_type": "Ed25519",
            "consensus_pubkey_b64": "{PUB_KEY}"
        }
    ],
    "launch_incentive_from": "0x35f517cab9a37bc31091c2f155d965af84e0bc85",
    "launch_incentive_to": "0x20a0bee429d6907e556205ef9d48ab6fe6a55531",
    "long_term_incentive": "0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07",
    "genesis_time": "{GENESIS_TIME}"
}
```

- Next, we generate the Genesis Configuration based on the configuration file.
```bash
$ ./target/debug/dev-utils genesis generate --genesis_dev_config_path ./dev-conf.json

"app_hash": "B3B873229A5FD2921801E592F3122B61C3CAE0C55FE0346369059F6643C751CC",
"app_state": {"distribution":{"0x20a0bee429d6907e556205ef9d48ab6fe6a55531":["2500000000000000000","ExternallyOwnedAccount"],"0x35f517cab9a37bc31091c2f155d965af84e0bc85":["2500000000000000000","ExternallyOwnedAccount"],"0x3a102b53a12334e984ef51fda0baab1768116363":["2500000000000000000","ExternallyOwnedAccount"],"0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de":["1250000000000000000","ExternallyOwnedAccount"],"0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07":["1250000000000000000","ExternallyOwnedAccount"]},"launch_incentive_from":"0x35f517cab9a37bc31091c2f155d965af84e0bc85","launch_incentive_to":"0x20a0bee429d6907e556205ef9d48ab6fe6a55531","long_term_incentive":"0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07","network_params":{"initial_fee_policy":{"constant":1001,"coefficient":1025},"required_council_node_stake":"1250000000000000000","unbonding_period":60},"council_nodes":[{"staking_account_address":"0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de","consensus_pubkey_type":"Ed25519","consensus_pubkey_b64":"EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE="}]}
```

We now have the initial App Hash as well as the App State. In the above example, the App Hash is  `B3B873229A5FD2921801E592F3122B61C3CAE0C55FE0346369059F6643C751CC`

<a id="start-chain-transaction-enclaves" />

### 5.3. Start Transaction Enclaves

Follow the instructions in [Crypto.com Chain Transaction Enclaves](https://github.com/crypto-com/chain-tx-enclave) to build and run the Chain Transaction Enclaves.

<a id="start-tendermint" />

### 5.4. Start Tendermint

- Update Tendermint Genesis Configuration

Copy the generated genesis configuration prepared previously and append it to `~/.tendermint/config/genesis.json` such that the file looks similar to this:
```json
{
  "genesis_time": "2019-05-21T09:47:56.206264Z",
  "chain_id": "test-chain-y3m1e6-AB",
  "consensus_params": {
    "block": {
      "max_bytes": "22020096",
      "max_gas": "-1",
      "time_iota_ms": "1000"
    },
    "evidence": { "max_age": "100000" },
    "validator": { "pub_key_types": ["ed25519"] }
  },
  "validators": [
    {
      "address": "91A26F2D061827567FE1E2ADC1C22206D4AD0FEF",
      "pub_key": {
        "type": "tendermint/PubKeyEd25519",
        "value": "MFgW9OkoKufCrdAjk7Zx0LMWKA/0ixkmuBpO0flyRtU="
      },
      "power": "10",
      "name": ""
    }
  ],
  "app_hash": "BA827BE4C6367614322C1727B5E752A5D2FA1B03E227D574A9DCDFA653EDB56D",
  "app_state": {
    "distribution": {
      "0x20a0bee429d6907e556205ef9d48ab6fe6a55531": [
        100000000000000000,
        "ExternallyOwnedAccount"
      ],
      "0x35f517cab9a37bc31091c2f155d965af84e0bc85": [
        100000000000000000,
        "ExternallyOwnedAccount"
      ],
      "0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de": [
        2500000000000000000,
        "ExternallyOwnedAccount"
      ],
      "0x3c747bbc06d1f57e66c6655f37d8157b4b3def96": [
        3000000000000000000,
        "ExternallyOwnedAccount"
      ],
      "0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07": [
        50000000000000000,
        "ExternallyOwnedAccount"
      ],
      "0xb63b606ac810a52cca15e44bb630fd42d8d1d83d": [
        1250000000000000000,
        "ExternallyOwnedAccount"
      ],
      "0xc3ea1251f8793456bb4435c50abf2ab2bfc99db6": [
        3000000000000000000,
        "ExternallyOwnedAccount"
      ]
    },
    "launch_incentive_from": "0x35f517cab9a37bc31091c2f155d965af84e0bc85",
    "launch_incentive_to": "0x20a0bee429d6907e556205ef9d48ab6fe6a55531",
    "long_term_incentive": "0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07",
    "network_params": {
      "initial_fee_policy": { "constant": 1055, "coefficient": 16 },
      "required_council_node_stake": 1250000000000000000,
      "unbonding_period": 60
    },
    "council_nodes": [
      {
        "staking_account_address": "0xb63b606ac810a52cca15e44bb630fd42d8d1d83d",
        "consensus_pubkey_type": "Ed25519",
        "consensus_pubkey_b64": "MFgW9OkoKufCrdAjk7Zx0LMWKA/0ixkmuBpO0flyRtU="
      }
    ]
  },
  "app_hash": "B3B873229A5FD2921801E592F3122B61C3CAE0C55FE0346369059F6643C751CC",
  "app_state": {"distribution":{"0x20a0bee429d6907e556205ef9d48ab6fe6a55531":["2500000000000000000","ExternallyOwnedAccount"],"0x35f517cab9a37bc31091c2f155d965af84e0bc85":["2500000000000000000","ExternallyOwnedAccount"],"0x3a102b53a12334e984ef51fda0baab1768116363":["2500000000000000000","ExternallyOwnedAccount"],"0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de":["1250000000000000000","ExternallyOwnedAccount"],"0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07":["1250000000000000000","ExternallyOwnedAccount"]},"launch_incentive_from":"0x35f517cab9a37bc31091c2f155d965af84e0bc85","launch_incentive_to":"0x20a0bee429d6907e556205ef9d48ab6fe6a55531","long_term_incentive":"0x71507ee19cbc0c87ff2b5e05d161efe2aac4ee07","network_params":{"initial_fee_policy":{"constant":1001,"coefficient":1025},"required_council_node_stake":"1250000000000000000","unbonding_period":60},"council_nodes":[{"staking_account_address":"0x3ae55c16800dc4bd0e3397a9d7806fb1f11639de","consensus_pubkey_type":"Ed25519","consensus_pubkey_b64":"EIosObgfONUsnWCBGRpFlRFq5lSxjGIChRlVrVWVkcE="}]}
}
```

- Start Tendermint Node

```bash
$ tendermint node
```

<a id="start-chain-abci" />

### 5.5. Start Chain ABCI

To start the Chain ABCI, you will need two pieces of data
- **App Hash**: Prepared in the [Generate Genesis](#generate-genesis) step
- **Full Chain ID**: Copy the `chain_id` found in `~/.tendermint/config/genesis.json` (e.g. test-chain-mafL4t-AA)

Run
```bash
$ chain-abci -g <APP_HASHx> -c <FULL_CHAIN_ID> --enclave_server tcp://127.0.0.1:25933
```

If you need backtraces or logging, set the environment variables before it:
```bash
$ RUST_BACKTRACE=1 RUST_LOG=info \
chain-abci \
-g <APP_HASH> \
-c <FULL_CHAIN_ID> \
--enclave_server tcp://127.0.0.1:25933
```

---

<a id="start-lite-node" />

## 6. Start a Basic Lite Node

```bash
$ tendermint lite
```

---

<a id="send-first-transaction" />

## 7. Send Your First Transaction

Genesis funds are bonded funds, to transfer freely around, you first have to withdraw to UTXO

- Create Transfer Address

```bash
$ ./target/debug/client-cli address new --name Default --type Transfer
crmt1k79pwssctn9dk3c5prd0gr54sr9a4azhc3xayl0gsvnn6hlnclhsypfj6y
```

- Withdrawal Bonded Funds

**staking address**: Previously generated address in your wallet to receive genesis funds
**transfer address**: Wallet Transfer address we just generated

```bash
$ ./target/debug/client-cli transaction new --chain-id AB --name Default --type Withdraw
Enter passphrase: 
Enter staking address: 0xbdb46d64ed9da69093490a578158b1a20d96370b
Enter transfer address: crmt1k79pwssctn9dk3c5prd0gr54sr9a4azhc3xayl0gsvnn6hlnclhsypfj6y
```

- Transfer CRO to another address

Work in Progresss

---

<a id="testing" />

## 8. Testing

To run the test cases
```bash
$ cargo test
```

To measure code coverage
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
* Community chatrooms (non-technical): [Discord](https://discord.gg/nsp9JTC) [Telegram](https://t.me/CryptoComOfficial)
* Developer community chatroom (technical): [![Gitter](https://badges.gitter.im/crypto-com/community.svg)](https://gitter.im/crypto-com/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
