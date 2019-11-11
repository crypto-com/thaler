#!/usr/bin/python3
import json
import requests
import datetime
import time

server = 'http://localhost:9981'
headers = {
    'Content-Type': 'application/json',
}


def show(a):
    print(json.dumps(a))


def list_wallet():
    q = {
        "method": "wallet_list",
        "jsonrpc": "2.0",
        "params": [],
        "id": "wallet_list"
    }
    data = json.dumps(q)
    response = requests.post(server, headers=headers, data=data)
    return response.json()["result"]


def create_staking_address(name, passphrase):
    q = {
        "method": "wallet_createStakingAddress",
        "jsonrpc": "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }],
        "id": "wallet_createStakingAddress"
    }
    data = json.dumps(q)
    response = requests.post(server, headers=headers, data=data)


def create_transfer_address(name, passphrase):
    q = {
        "method": "wallet_createTransferAddress",
        "jsonrpc": "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }],
        "id": "wallet_createTransferAddress"
    }
    data = json.dumps(q)
    response = requests.post(server, headers=headers, data=data)


def restore_wallet(name, passphrase, mnemonics):
    q = {
        "method": "wallet_restore",
        "jsonrpc": "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }, mnemonics],
        "id": "wallet_restore_hd"
    }
    data = json.dumps(q)
    response = requests.post(server, headers=headers, data=data)


def list_staking_address(name, passphrase):
    q = {
        "method": "wallet_listStakingAddresses",
        "jsonrpc": "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }],
        "id": "wallet_listStakingAddresses"
    }
    data = json.dumps(q)
    response = requests.post(server, headers=headers, data=data)
    return response.json()["result"]


def list_trasfer_address(name, passphrase):
    q = {
        "method": "wallet_listTransferAddresses",
        "jsonrpc": "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }],
        "id": "wallet_listTransferAddresses"
    }
    data = json.dumps(q)
    response = requests.post(server, headers=headers, data=data)
    return response.json()["result"]


def get_staking_state(name, passphrase, addr):
    q = {
        "method": "staking_state",
        "jsonrpc": "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }, addr],
        "id": "staking_state"
    }
    data = json.dumps(q)
    response = requests.post(server, headers=headers, data=data)
    return response.json()["result"]


def withdraw_all_unbonded(name, passphrase, from1, to, viewkeys):
    q = {
        "method": "staking_withdrawAllUnbondedStake",
        "jsonrpc": "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }, from1, to, viewkeys],
        "id": "staking_withdrawAllUnbondedStake"
    }
    data = json.dumps(q)
    response = requests.post(server, headers=headers, data=data)
    return response.json()


def deposit(name, passphrase, to, utxos):
    q = {
        "method": "staking_depositStake",
        "jsonrpc": "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }, to, utxos],
        "id": "staking_depositStake"
    }
    data = json.dumps(q)
    print("data= %s" % data)
    response = requests.post(server, headers=headers, data=data)
    print(response.json())
    return response.json()["result"]


def get_viewkey(name, passphrase):
    q = {
        "method": "wallet_getViewKey",
        "jsonrpc": "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }],
        "id": "wallet_getViewKey"
    }
    data = json.dumps(q)
    response = requests.post(server, headers=headers, data=data)
    return response.json()["result"]


def get_balance(name, passphrase):
    q = {
        "method": "wallet_balance",
        "jsonrpc": "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }],
        "id": "wallet_balance"
    }
    data = json.dumps(q)
    response = requests.post(server, headers=headers, data=data)
    return response.json()["result"]


def sync(name, passphrase):
    q = {
        "method": "sync",
        "jsonrpc": "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }],
        "id": "sync"
    }
    data = json.dumps(q)
    response = requests.post(server, headers=headers, data=data)
    return response.json()


def tranactions(name, passphrase):
    q = {
        "method": "wallet_transactions",
        "jsonrpc": "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }],
        "id": "wallet_transactions"
    }
    data = json.dumps(q)
    response = requests.post(server, headers=headers, data=data)
    return response.json()["result"]


def send_amount(name, passphrase, to, amount_in_carson, viewkeys):
    q = {
        "method":
        "wallet_sendToAddress",
        "jsonrpc":
        "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }, to, amount_in_carson, viewkeys],
        "id":
        "wallet_sendToAddress"
    }
    data = json.dumps(q)
    response = requests.post(server, headers=headers, data=data)
    return response.json()


def test_transfer():
    av = get_viewkey("a", "1")
    assert "02e8b3ce9ba835b9508535d11f4e823210ca2b6005ab5a71edd4659ab450573391" == av
    bv = get_viewkey("b", "1")
    assert "03bad1214ef56af812ee8981c534569b69e00a00943bf07f4b260544bd2e08b856" == bv
    withdraw_all_unbonded(
        "a", "1", "0xe5b4b42406a061752c78bf5c4d6d6fccca0b575f",
        "dcro13z2xw689qhpmv7ge9xg428ljg4848rtu5dcpdmxy3m6njdsjtd3sl30d8n",
        [av, bv])
    print("wait for processing")
    time.sleep(10)
    get_staking_state("a", "1", "0xe5b4b42406a061752c78bf5c4d6d6fccca0b575f")
    show_balances()
    b_balance = int(get_balance("b", "1"))

    amount = 200000001
    print("send amount %d carson" % amount)
    send_amount(
        "a", "1",
        "dcro18gcxmetst2vnq82j35gn2963wy2e0jcp5cc2kefr6hzmzgqczu3qj3yvj9",
        str(amount), [av, bv])
    print("wait for processing")
    time.sleep(10)

    #txs_a = tranactions("a", "1")
    #txs_b = tranactions("b", "1")
    print("wait for processing")
    time.sleep(10)
    show_balances()
    b_new_balance = int(get_balance("b", "1"))
    assert b_balance + amount == b_new_balance


def create_addresses():
    create_staking_address("a", "1")
    create_transfer_address("a", "1")
    create_staking_address("b", "1")
    create_transfer_address("b", "1")


def list_addresses():
    a_staking = list_staking_address("a", "1")
    a_transfer = list_trasfer_address("a", "1")
    b_staking = list_staking_address("b", "1")
    b_transfer = list_trasfer_address("b", "1")
    print("a staking=%s" % json.dumps(a_staking))
    print("------------------------------------------")
    print("a transfer=%s" % json.dumps(a_transfer))
    print("------------------------------------------")
    print("b staking=%s" % json.dumps(b_staking))
    print("------------------------------------------")
    print("b transfer=%s" % json.dumps(b_transfer))
    print("------------------------------------------")


def restore_wallets():
    restore_wallet(
        "a", "1",
        "speed tortoise kiwi forward extend baby acoustic foil coach castle ship purchase unlock base hip erode tag keen present vibrant oyster cotton write fetch"
    )
    restore_wallet(
        "b", "1",
        "humor lend song cream certain tackle digital science hold dry fence project ski bundle average room protect assume delay wreck athlete chapter author ancient"
    )


def show_balances():
    sync("a", "1")
    a_balance = int(get_balance("a", "1"))
    print("a balance %d carson" % a_balance)

    sync("b", "1")
    b_balance = int(get_balance("b", "1"))
    print("b balance %d carson" % b_balance)


def program():
    # restore wallets
    restore_wallets()
    wallets = list_wallet()
    print(wallets)

    create_addresses()
    test_transfer()
    list_addresses()

    show_balances()
    b_txs = tranactions("b", "1")
    utxo = b_txs[0]["transaction_id"]
    print("b txs= %s" % json.dumps(b_txs[0]))
    print("utxo = %s" % utxo)

    sync("b", "1")
    newtx = deposit("b", "1", "0x0bfbb3857f8daf13f9b7651dd4986671bf4c7a0e",
                    [{
                        "id": utxo,
                        "index": 0
                    }])
    time.sleep(10)
    sync("b", "1")
    b_staking = get_staking_state(
        "b", "1", "0x0bfbb3857f8daf13f9b7651dd4986671bf4c7a0e")
    print("deposit result %s" % newtx)
    print("state %s" % b_staking)


#main
program()
