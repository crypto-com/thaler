#!/bin/bash
cd "$(dirname "${BASH_SOURCE[0]}")"

if [ -f data/supervisord.pid ]; then
    echo 'Quit supervisord...'
    kill -QUIT `cat data/supervisord.pid` 2> /dev/null && sleep 3
fi
if [ -f supervisord.log ]; then
    rm -f supervisord.log
fi
if [ -d data ]; then
    rm -rf data
fi
if [ -d data_offline ]; then
    rm -rf data_offline
fi
if [ -L tx-query2-enclave-app.sgxs ]; then
    rm -f tx-query2-enclave-app.sgxs
fi
if [ -L tx-query2-enclave-app.sig ]; then
    rm -f tx-query2-enclave-app.sig
fi
if [ -L tx_validation_enclave.signed.so ]; then
    rm -f tx_validation_enclave.signed.so
fi
exit 0
