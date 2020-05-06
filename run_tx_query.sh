set -e

APP_NAME=tx-query2-enclave-app
RUNNER_NAME=tx-query2-app-runner

# Execute
./target/debug/$RUNNER_NAME target/x86_64-fortanix-unknown-sgx/debug/$APP_NAME.sgxs