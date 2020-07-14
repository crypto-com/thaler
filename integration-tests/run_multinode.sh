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
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"../target"}
BUILD_PROFILE=${BUILD_PROFILE:-debug}
EDP_TARGET_DIR=$CARGO_TARGET_DIR/x86_64-fortanix-unknown-sgx/$BUILD_PROFILE
BUILD_MODE=${BUILD_MODE:-sgx}
ln -sf $CARGO_TARGET_DIR/$BUILD_PROFILE/tx_validation_enclave.signed.so .
ln -sf $EDP_TARGET_DIR/tx-query2-enclave-app.sgxs .
ln -sf $EDP_TARGET_DIR/tx-query2-enclave-app.sig .
export PATH=$CARGO_TARGET_DIR/$BUILD_PROFILE:$PATH

if [ $BUILD_MODE == "sgx" ]; then
    CHAINBOT_ARGS=
else
    CHAINBOT_ARGS="--mock-mode"
fi

# environment variables for integration tests
export PASSPHRASE=123456
export BASE_PORT=${BASE_PORT:-26650}
export TENDERMINT_RPC_PORT=$(($BASE_PORT + 7))

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
    # ra-sp-server
    wait_port 8989 &&
    # tendermint rpc of first node
    wait_port $TENDERMINT_RPC_PORT
}

function runtest() {
    echo "Preparing... $1"
    chainbot.py prepare multinode/$1_cluster.json --base_port $BASE_PORT $CHAINBOT_ARGS
    export CRYPTO_GENESIS_FINGERPRINT=`python -c "import json; print(json.load(open('data/info.json'))['genesis_fingerprint'])"`
    echo "genesis fingerprint: $CRYPTO_GENESIS_FINGERPRINT"

    echo "Startup..."
    supervisord -n -c data/tasks.ini &
    if ! wait_service; then
        echo 'tendermint of first node still not ready, giveup.'
        RETCODE=1
    else
        set +e
        python -u ./multinode/$1_test.py
        RETCODE=$?
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

runtest "join" # non-live fault slash, re-join, unbond, re-join
runtest "byzantine" # make byzantine fault and check jailed, then unjail and re-join again
runtest "multitx" # make multiple transactions in one block
runtest "reward" # check reward amount, no reward for jailed node

./cleanup.sh
