<p align="center">
  <img src="https://avatars0.githubusercontent.com/u/41934032?s=400&v=4" alt="Crypto.com Chain" width="400">
</p>

<h2 align="center">(Work in Progress) <a href="https://crypto.com">Crypto.com<a> Chain Transaction Enclaves</h2>

For more details, see the [Crypto.com Chain README](https://github.com/crypto-com/chain)

## Common Parameters

- `SGX_MODE`:
  - `SW` for Software Simulation mode
  - `HW` for Hardware mode
- `NETWORK_HEX_ID`: Network HEX Id of Tendermint
- `APP_PORT`: Listening Port inside the Docker instance (Default: 25933)

## Docker

### Build the Docker image
```bash
$ docker build -t chain-tx-validation \
-f ./tx-validation/Dockerfile . \
--build-arg SGX_MODE=<SW|HW> \
--build-arg NETWORK_ID=<NETWORK_HEX_ID>

# Example
$ docker build -t chain-tx-validation \
-f ./tx-validation/Dockerfile . \
--build-arg SGX_MODE=SW \
--build-arg NETWORK_ID=AB
```

### Run the Docker instance

- Software Simulation Mode
```bash
# docker run --rm -p <HOST_PORT>:<DOCKER_APP_PORT> -rm chain-tx
$ docker run --rm \
-p 25933:25933 \
--env RUST_BACKTRACE=1 \
--env RUST_LOG=info \
chain-tx-validation
```

- Hardware Mode
```bash
# docker run --rm --device /dev/isgx -p <HOST_PORT>:<DOCKER_APP_PORT> chain-tx
$ docker run --rm \
--device /dev/isgx \
-p 25933:25933 \
--env RUST_BACKTRACE=1 \
--env RUST_LOG=info \
chain-tx-validation
```

#### Bind enclave storage to local storage

Encalve contains its own state stored inside Docker instance, if you are restarting the Docker, you may experience sanity check error because by default the docker storage is cleared on teardown.

To solve the problem, consider binding your host storage to the `/enclave-storage` of the instance by:
```bash
$ docker run --rm \
-p 25933:25933 \
--env RUST_BACKTRACE=1 \
--env RUST_LOG=info \
-v /User/crypto-com/enclave-storage:/enclave-storage \
chain-tx-validation
```

Replace `/User/crypto-com/enclave-storage` with your desired host path. Note that host storage path must be an absolute path.

### Run /bin/bash inside Docker instance

If you want to get your hands dirty, you can
```bash
$ docker run --rm \
chain-tx-validation \
/bin/bash
```

## Update Rust SGX SDK

```bash
$ make -f UpdateRustSGXSDK.mk
```

Commit the updated Rust SGX SDK in your forked branch and create a [Pull Request](https://github.com/crypto-com/chain-tx-enclave/pulls) to this repository.
