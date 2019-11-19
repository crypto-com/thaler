#!/bin/bash
./chain-abci --host 0.0.0.0 --port 26658 --chain_id test-ab  --genesis_app_hash  C8B1101B2FDF6684046C4F0E6BEE9FE595433AAC5200A3EFFD7CC77A9FD27E7C     --enclave_server tcp://127.0.0.1:25933
