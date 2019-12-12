#!/bin/bash
./chain-abci --host 0.0.0.0 --port 26658 --chain_id test-ab  --genesis_app_hash  $APP_HASH   --enclave_server tcp://127.0.0.1:25933 --tx_query tcp://127.0.0.1:25933
