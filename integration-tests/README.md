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

## List of Integration Tests

| Integration Test Suite | Description |
| --- | --- |
| run-test.sh | Test Tendermint, Chain ABCI and ClientRPC are connect together |

## How to spin up and teardown Docker Compose Services

Go to the `integration-tests` folder, run

### Spin up
```bash
$ docker-compose up
```

### Teardown
```bash
$ docker-compose down
```

## How to run  Integration Tests Suite

1. Build and spin up Docker containers
2. Go to the `integration-tests` folder, run
```bash
$ ./run-test.sh
```
