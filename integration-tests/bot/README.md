Prerequisite
============

* [tendermint](https://tendermint.com/downloads) in PATH.
* [docker](https://docs.docker.com/install/) with ``integration-tests-chain-tx-enclave`` (or ``integration-tests-chain-tx-enclave-sw`` for software mode) image inside.
* binaries ``dev-utils`` ``client-cli`` ``chain-abci`` ``client-rpc`` in PATH.
* python3.7+

Install
=======

```
$ pip3 install git+https://github.com/yihuang/crypto-chain-bot.git
```

OR:

```
  $ git clone https://github.com/yihuang/crypto-chain-bot.git
  $ cd crypto-chain-bot
  $ pip3 install -e .
```

Usage
=====

    $ cd /path/to/testnet
    $ chainbot.py gen 2 > cluster.json
    $ cat cluster.json
    {
        "genesis_time": "2019-11-20T08:56:48.618137Z",
        "rewards_pool": 0,
        "nodes": [
            {
                "name": "node0",
                "mnemonic": "sea hurdle public diesel family mushroom situate nasty act young smoke fantasy olive paddle talent",
                "validator_seed": "da65e6e809413a217b03f77bb00800e9c36d8a2f11ff00669c412ec34e077225",
                "node_seed": "dbbdd0c1e8ca293cd90ce9f417224bdfafdccb70e43cb2ed1732b2884c553773",
                "bonded_coin": 2500000000000000000,
                "unbonded_coin": 2500000000000000000,
                "base_port": 26650
            },
            {
                "name": "node1",
                "mnemonic": "absent noble used scout unfair cannon attack brass review scrap soap legal sugar carpet warrior",
                "validator_seed": "60ab92ba36ab4222ea4f986ea060399bb550ae6f7b7f885e69c9b0bbe88be39d",
                "node_seed": "e2fc20e58511b7e313488cc953dc09ebae4fb50145170ffdd0fe159627d5f5d3",
                "bonded_coin": 2500000000000000000,
                "unbonded_coin": 2500000000000000000,
                "base_port": 26660
            }
        ],
        "config_patch": [
            {
                "op": "replace",
                "path": "/initial_fee_policy/base_fee",
                "value": "0.0"
            },
            {
                "op": "replace",
                "path": "/initial_fee_policy/per_byte_fee",
                "value": "0.0"
            }
        ]
    }
    $ chainbot.py prepare cluster.json
    $ ls -1 .
    node0
    node1
    tasks.ini
    cluster.json
    $ supervisord -n -c tasks.ini

Manage the running processes:

    $ supervisorctl -c tasks.ini
    node0:chain-abci-node0           RUNNING   pid 12080, uptime 0:00:13
    node0:client-rpc-node0           RUNNING   pid 12096, uptime 0:00:10
    node0:tendermint-node0           RUNNING   pid 12065, uptime 0:00:14
    node0:tx-enclave-node0           RUNNING   pid 12064, uptime 0:00:14
    node1:chain-abci-node1           RUNNING   pid 12081, uptime 0:00:13
    node1:client-rpc-node1           RUNNING   pid 12097, uptime 0:00:10
    node1:tendermint-node1           RUNNING   pid 12068, uptime 0:00:14
    node1:tx-enclave-node1           RUNNING   pid 12067, uptime 0:00:14

Port Usage
==========

* base-port: 26650 + (node_index * 10)
* tendermint-p2p-port: base-port + 6
* tendermint-rpc-port: base-port + 7
* chain-abci: base-port + 8
* tx-enclave: base-port + 0
* client-rpc-port: base-port + 9

``chainrpc.py``
===============

Wallet RPC
----------

    $ chainrpc.py wallet restore 'winter kit mistake video congress crucial cement gaze seven certain fog cloud jeans brisk glue'
    Default
    $ chainrpc.py address list
    0x7c1691e7ff768c83da2a2a6e22484adefc746c8f
    $ chainrpc.py address create
    0xda360623ad8a10360ff7afc9311b8dc0db024e98
    $ chainrpc.py staking state 0xda360623ad8a10360ff7afc9311b8dc0db024e98
    address:       0xda360623ad8a10360ff7afc9311b8dc0db024e98
    bonded:        0
    council_node:  null
    nonce:         0
    punishment:    null
    unbonded:      5000000000000000000
    unbonded_from: 1574240208
    $ chainrpc.py address list --type transfer
    dcro14rd97zpjh38a9l9sza4z7zzatfyjas04xy0yq3v75hmxdju7cwrs94yn76
    $ chainrpc.py staking withdraw_all_unbonded_stake 0xda360623ad8a10360ff7afc9311b8dc0db024e98 dcro14rd97zpjh38a9l9sza4z7zzatfyjas04xy0yq3v75hmxdju7cwrs94yn76
    d68732a45412f319b10e1bfe025e724c1e61e0a8ef80e8f490919cb4ed526b8c
    $ chainrpc.py wallet balance
    0
    $ chainrpc.py wallet sync
    $ chainrpc.py wallet balance
    5000000000000000000

Tendermint RPC
---------------

    $ chainrpc.py chain status
    node_info:      {"protocol_version": {"p2p": "7", "block": "10", "app": "0"}, "id": "3135de411a5028c61c12ab6635add83ead051342", "listen_addr": "tcp://0.0.0.0:26656", "network": "test-chain-y3m1e6-AB", "version": "0.32.7", "channels": "4020212223303800", "moniker": "node0", "other": {"tx_index": "on", "rpc_address": "tcp://127.0.0.1:26657"}}
    sync_info:      {"latest_block_hash": "A4C30E0C9A2DC3630233AE8DD9459588CFE7994E6E47C0AE017FEB00AC119AE0", "latest_app_hash": "97500A2754824891C5E56FD39DCD2B670331232FDD9ABDCA07453E5F97F8D856", "latest_block_height": "180", "latest_block_time": "2019-11-26T08:45:42.203115Z", "catching_up": false}
    validator_info: {"address": "9004A42E6DD6E4D0A088F26EFF11A2DF699D0238", "pub_key": {"type": "tendermint/PubKeyEd25519", "value": "1GcI44AMk2O0puoBBszFCSzWIxlGQP8qOGiGBqUJ+Lk="}, "voting_power": "50000000000"}
