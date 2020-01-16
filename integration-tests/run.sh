#!/bin/bash
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

# cleanup first
./cleanup.sh

# ensure dependencies for integration tests
./deps.sh
PYTHON_VENV_DIR=${PYTHON_VENV_DIR:-"./bot/.venv"}
source $PYTHON_VENV_DIR/bin/activate

# prepare chain binaries
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"../target"}
ln -sf $CARGO_TARGET_DIR/debug/tx_query_enclave.signed.so .
ln -sf $CARGO_TARGET_DIR/debug/tx_validation_enclave.signed.so .
export PATH=$CARGO_TARGET_DIR/debug:$PATH

# environment variables for integration tests
export PASSPHRASE=123456
export BASE_PORT=${BASE_PORT:-26650}
export CLIENT_RPC_PORT=$(($BASE_PORT + 9))
export TENDERMINT_RPC_PORT=$(($BASE_PORT + 7))
export CLIENT_RPC_ZEROFEE_PORT=$CLIENT_RPC_PORT
export TENDERMINT_ZEROFEE_RPC_PORT=$TENDERMINT_RPC_PORT

function wait_http() {
    for i in $(seq 0 10);
    do
        curl -s "http://127.0.0.1:$1" > /dev/null
        if [ $? -eq 0 ]; then
            return 0
        fi
        sleep 2
    done
    return 1
}

function runtest() {
    echo "Preparing... $1"
    LOWERED_TYPE=`echo $1 | tr "[:upper:]" "[:lower:]"`
    chainbot.py prepare ${LOWERED_TYPE}_cluster.json --base_port $BASE_PORT

    echo "Startup..."
    supervisord -n -c data/tasks.ini &
    if ! wait_http $CLIENT_RPC_PORT; then
        echo 'client-rpc still not ready, giveup.'
        cat data/logs/*.log
        RETCODE=1
    else
        set +e

        pushd client-rpc
        TEST_ONLY=$1 npm run test
        RETCODE=$?
        popd

        if [ $RETCODE -eq 0 ]; then
            pytest pytests
            RETCODE=$?
        fi

        set -e
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
