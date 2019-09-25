
# Transaction Decryption Query Enclave

This transaction enclave allows semi-trusted client querying of sealed transaction payloads that were persisted by the transaction validation enclave on the same machine.

For more details on the client side, see the [Crypto.com Chain README](https://github.com/crypto-com/chain) and `client-index`.

## Build / Run
This only works / makes sense in the hardware mode, see the [main README](../README.md).

1. start the AESM Service / make sure it is running. For example, inside the Docker container, run:
```
LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service &
```

2. (if not done before) Build and run the [transaction validation enclave](../tx-validation).

3. Build by `tx-query` running `make` 

4. Make sure the below *required* environment variables are set and run `./tx-query-app <address:port to listen on> <tx-validation ZMQ connection string>`

### Required Environment Variables

You can obtain the SPID and API key (choose -- unlinkable quotes) here: https://api.portal.trustedservices.intel.com/EPID-attestation

- `SPID`: "Service Provider ID" 
- `IAS_API_KEY`: the primary or secondary API key for querying the Intel Attestation Service

### Optional Environment Variables
- `RUST_LOG`
- `RUST_BACKTRACE`

## (tx-validation "integration") Test
1. start the AESM Service / make sure it is running. For example, inside the Docker container, run:
```
LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service &
```

2. (if not done before) Build (non-test) the [transaction validation enclave](../tx-validation).

3. Build by running `SGX_TEST=1 make` 

4. Make sure the above *required* environment variables are set

5. Additional, set the `TX_VALIDATION_BIN_DIR` environment variable to the directory path where `tx-validation-app` binary resides

6. Run `./tx-query-app`