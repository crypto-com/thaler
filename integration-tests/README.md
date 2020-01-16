# Crypto.com Chain Client Integration Tests Suite

## Run locally

Prerequisite:

* Linux with sgx device and `aesm_service` started
* chain binaries in `PATH`, `./target/debug` directory will be added to `PATH` atomatically.
* python3.7+ and npm.

Run:

```shell
./integration-tests/run.sh
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
drone exec --secret-file secretfile --trusted
```

You can also use `--exclude` to choose to run unit test or integration test (refer to docs of drone-cli for more detail):

```shell
# run integration tests only
drone exec --secret-file secretfile --trusted --exclude unit-tests
# run unit tests only
drone exec --secret-file secretfile --trusted --exclude integration-tests
```
