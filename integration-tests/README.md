# Thaler Experimental Network Client Integration Tests Suite

## Environment Variables

```
BUILD_PROFILE = debug|release  # default to debug
BUILD_MODE = sgx|mock  # default to sgx
```

## Run locally with sgx

Prerequisite:

* Linux with sgx device and `aesm_service` started
* rust dev stuff.
* python3.7+ and npm.

Build:

```shell
./docker/build.sh
```

Run:

```shell
# single node integration tests
./integration-tests/run.sh
# multi-node integration tests
./integration-tests/run_multinode.sh
```

## Run locally with drone

> We assume the name of sgx device is `/dev/sgx`, if you have a different device name, you need to rename it by creating permanent symbolic link like this:
>
> ```shell
> $ cat > /etc/udev/rules.d/99_sgx.rules << EOF
> KERNEL=="isgx", SYMLINK+="sgx"
> EOF
> $ reboot
> ```

Prerequisite:

* Linux with sgx device

* [drone-cli](https://docs.drone.io/cli/install/)

- [docker](https://www.docker.com/get-started)

Prepare secret file with `SPID` and `IAS_API_KEY` inside.

Run:

```shell
drone exec --secret-file secretfile --trusted --exclude restore-cache --exclude rebuild-cache
```

You can also use `--include/--exclude` to choose to run different steps (refer to docs of drone-cli for more detail):

```shell
# only run unit-tests
drone exec --secret-file secretfile --trusted --include build --include unit-tests
# only run single node integration tests
drone exec --secret-file secretfile --trusted --include build --include integration-tests --include teardown
# only run multi node integration tests
drone exec --secret-file secretfile --trusted --include build --include multinode-tests --include teardown
```

## Run locally in mock mode

Set `BUILD_MODE=mock`, then refer to above instructions.

## Run locally with drone in mock mode

```
$ cat > .drone.env << EOF
BUILD_MODE=mock
EOF
$ drone exec drone.test.yml --secret-file secretfile --env-file .drone.mockenv --trusted --exclude restore-cache --exclude rebuild-cache
```

## Run manually

> In development or debugging, you may want run the test manually.

Prerequisite:
* Linux with sgx device and `aesm_service` started for sgx mode.
* All the development dependencies.
* Environment variables: `SGX_SDK`/`NETWORK_ID`/`SPID`/`IAS_API_KEY`.

```
$ cd integration-tests
```

#### Build

```
$ ../docker/build.sh
```

#### First time preparation

> Only needs to run this at the first time.

```
$ ./deps.sh
```

#### Environment setup

```
$ source bot/.venv/bin/activate
$ export PATH=../target/debug:$PATH
$ ln -s ../target/debug/tx_query_enclave.signed.so .
$ ln -s ../target/debug/tx_validation_enclave.signed.so .
```

#### Chain preparation

> Choose an unique base port when using shared machine.

- Single node testnet:

  ```
  $ chainbot.py prepare zerofee_cluster.json --base_port=27750
  ```

- Multiple nodes testnet:

  ```
  $ chainbot.py prepare multinode/jail_cluster.json --base_port=27750
  ```

#### Run testnet

```
$ supervisord -n -c data/tasks.ini
$
$ # wait for nodes startup and run test
$ BASE_PORT=27750 chainrpc.py wallet list
$
$ cd client-rpc
$ # no need to set ports if no custom `--base_port`
$ TEST_ONLY=ZERO_FEE CLIENT_RPC_ZEROFEE_PORT=27759 TENDERMINT_ZEROFEE_RPC_PORT=27757 npm run test
```

#### Clean up

```
$ ./cleanup.sh
```
