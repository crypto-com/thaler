# Crypto.com Chain Client Integration Tests Suite

## Prerequisites

- [Docker](https://www.docker.com/get-started)
- [jq](https://stedolan.github.io/jq/)

## Prepare Integration Test

### Initialize Tendermint and genesis

Note: This step is needed only in local environment. TravisCI will initialize the data and build automatically.

1\. Build the [Crypto.com chain](https://www.github.com/crypto-com/chain) project.

2\. Go to the `integration-tests` folder, run

```bash
$ ./prepare.sh
```

## Start Local Integration Tests environment

There are two ways you can start the local integration tests environment for testing:

### 1. Start using your local chain code

The environment used your local build, which is suitable when you are under active development.

- **When to use**: Under active development
- **Advantages**: Using your local build gives faster build time and feedback loop
- **Disadvantages**: Takes more steps to setup

#### Howto

You have to start each component one-by-one using the provided script, each component has normal (With fee) mode and zero-fee mode. Suffix the component name with `-zerofee` for zero-fee mode.

e.g. `tendermint` to `tendermint-zerofee`

#### Start Chain Tx Enclave

```bash
$ ./integration-tests/start-local.sh chain-tx-enclave
# Or
$ ./integration-tests/start-local.sh chain-tx-enclave-zerofee
```

#### Start Tendermint

```bash
$ ./integration-tests/start-local.sh tendermint
# Or
$ ./integration-tests/start-local.sh tendermint-zerofee
```

#### Start Chain ABCI

```bash
$ ./integration-tests/start-local.sh chain-abci
# Or
$ ./integration-tests/start-local.sh chain-abci-zerofee
```

#### Start ClientRPC

```bash
$ ./integration-tests/start-local.sh client-rpc
# Or
$ ./integration-tests/start-local.sh client-rpc-zerofee
```

### 2. Start using Docker Compose

The environment will be built on-the-fly on docker-compose, which does not require much human intervention but has to be re-built from scratch whenever code changes.

- **When to use**: One-off running of integration tests
- **Advantages**: The whole environment is built and started with one command
- **Disadvantages**: Since docker manages the build for you, docker has to re-build on every code changes

#### Howto

```bash
$ . ./integration-tests/env.sh
$ docker-compose -f ./integration-tests/docker-compose.yml up
```

## List of Integration Tests

| Integration Test Suite | Description                                                    |
| ---------------------- | -------------------------------------------------------------- |
| run-test.sh            | Test Tendermint, Chain ABCI and ClientRPC are connect together |
| client-rpc | Test related to client RPC server operations |

## How to run `client-rpc` Integration Tests Suite

Go to `client-rpc` directory, run
```bash
$ yarn
$ yarn test
```

## Appendix

### Initialized Wallet

The wallet initialized by the prepare script contains a wallet named `Default` with passpharse `123456`. An initial genesis funds of `2500000000000000000` basic unit of CRO is bonded to the first address of the wallet.

### Update Tendermint version

There are two places specifying Tendermint version to build and run:
- integration-tests/constant-env.sh
- integration-tests/docker-compose.yml

If you want to specify your Tendermint version, you can also set environment `TENDERMINT_VERSION` to your desired version before prepare, build and start.
