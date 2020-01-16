#!/bin/bash
cd "$(dirname "${BASH_SOURCE[0]}")"

if [ -f data/supervisord.pid ]; then
    kill -QUIT `cat data/supervisord.pid` && sleep 3
fi
rm supervisord.log 2> /dev/null
rm -r data 2> /dev/null
rm tx_query_enclave.signed.so 2> /dev/null
rm tx_validation_enclave.signed.so 2> /dev/null
exit 0
