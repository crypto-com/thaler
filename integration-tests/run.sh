#!/bin/bash
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

# cleanup first
./cleanup.sh

# ensure dependencies for integration tests
./deps.sh
PYTHON_VENV_DIR=${PYTHON_VENV_DIR:-"./.venv"}
source $PYTHON_VENV_DIR/bin/activate

# prepare chain binaries
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"../target"}
BUILD_PROFILE=${BUILD_PROFILE:-debug}
BUILD_MODE=${BUILD_MODE:-sgx}
EDP_TARGET_DIR=$CARGO_TARGET_DIR/x86_64-fortanix-unknown-sgx/$BUILD_PROFILE
ln -sf $CARGO_TARGET_DIR/$BUILD_PROFILE/tx_validation_enclave.signed.so .
ln -sf $EDP_TARGET_DIR/tx-query2-enclave-app.sgxs .
ln -sf $EDP_TARGET_DIR/tx-query2-enclave-app.sig .
ln -sf $EDP_TARGET_DIR/tdb-enclave-app.sgxs .
ln -sf $EDP_TARGET_DIR/tdb-enclave-app.sig .
ln -sf $EDP_TARGET_DIR/tx-validation-next.sgxs .
ln -sf $EDP_TARGET_DIR/tx-validation-next.sig .
export PATH=$CARGO_TARGET_DIR/$BUILD_PROFILE:$PATH

if [ $BUILD_MODE == "sgx" ]; then
    CHAINBOT_ARGS=
else
    CHAINBOT_ARGS="--mock-mode"
fi

# environment variables for integration tests
export PASSPHRASE=123456
export BASE_PORT=${BASE_PORT:-26650}
export CLIENT_RPC_PORT=$(($BASE_PORT + 9))
export TENDERMINT_RPC_PORT=$(($BASE_PORT + 7))
export CLIENT_RPC_ZEROFEE_PORT=$CLIENT_RPC_PORT
export TENDERMINT_ZEROFEE_RPC_PORT=$TENDERMINT_RPC_PORT

function wait_port() {
    echo "Wait for tcp port $1"
    for i in $(seq 0 20);
    do
        python -c "import socket; sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.connect(('127.0.0.1', $1))" 2> /dev/null
        if [ $? -eq 0 ]; then
            echo "Tcp port $1 is available now"
            return 0
        fi
        echo "[`date`] Tcp port $1 not available yet, sleep 2 seconds and retry"
        sleep 2
    done
    return 1
}

function wait_service() {
    if [ $BUILD_MODE == "sgx" ]; then
      # ra-sp-server
      wait_port 8989
    fi
    # tendermint rpc of first node
    wait_port $TENDERMINT_RPC_PORT
}

function runtest() {
    echo "Preparing... $1"
    LOWERED_TYPE=`echo $1 | tr "[:upper:]" "[:lower:]"`
    chainbot.py prepare ${LOWERED_TYPE}_cluster.json --base_port $BASE_PORT --start_client_rpc $CHAINBOT_ARGS
    export CRYPTO_GENESIS_FINGERPRINT=`python -c "import json; print(json.load(open('data/info.json'))['genesis_fingerprint'])"`
    export CRYPTO_CHAIN_ID=`python -c "import json; print(json.load(open('data/info.json'))['chain_id'])"`
    export CRYPTO_CLIENT_STORAGE=`pwd`/data/wallet
    echo "genesis fingerprint: $CRYPTO_GENESIS_FINGERPRINT"
    echo "crypto_chain_id: $CRYPTO_CHAIN_ID"


    echo "Startup..."
    supervisord -n -c data/tasks.ini &
    if ! wait_service; then
        echo 'tendermint rpc not ready, giveup.'
        RETCODE=1
    else
        set +e

        pushd client-rpc
        TEST_ONLY=$1 npm run test
        RETCODE=$?
        popd

        supervisorctl -c data/tasks.ini stop node0:client-rpc-node0

        if [ $RETCODE -eq 0 ]; then
			if [ $1 == "WITH_FEE" ]; then
				pytest pytests -m "not zerofee"
			else
				pytest pytests -m "not withfee"
			fi
            RETCODE=$?
        fi

        set -e
    fi

    if [ $RETCODE -ne 0 ]; then
        tail -n 100 data/logs/*.log
    fi

    echo "Quit supervisord..."
    kill -QUIT `cat data/supervisord.pid`
    wait
    rm -r data
    rm supervisord.log

    return $RETCODE
}

if [ -d data ]; then
    echo "Last run doesn't quit cleanly, please quit supervisord daemon and remove integration-tests/data manually."
    exit 1;
fi

runtest "WITH_FEE"
runtest "ZERO_FEE"

./cleanup.sh
