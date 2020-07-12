import json
import pytest
import os
import time
from client_cli import Wallet, Transaction

PASSPHRASE = "123456"
CRO = 10**8

def delete_all_wallet():
    wallet_names = Wallet.list()
    wallet_list = [Wallet(name, PASSPHRASE) for name in wallet_names]
    for wallet in wallet_list:
        wallet.delete()
    wallet_names = Wallet.list()
    assert not wallet_names


def write_wallet_info_to_file(wallet_list, from_file = "/tmp/from_file"):
    wallet_info = [{"name": w.name, "auth_token": w.auth_token} for w in wallet_list]
    with open(from_file, "w") as f:
        json.dump(wallet_info, f)


@pytest.mark.zerofee
def test_wallet_basic():
    # 1. create wallet
    wallet_name_list = ["test1", "test2"]
    wallet_list = []
    for name in wallet_name_list:
        wallet = Wallet(name, PASSPHRASE)
        wallet.new("basic")
        wallet_list.append(wallet)
    wallet_name_list = ["test3", "test4"]
    for name in wallet_name_list:
        wallet = Wallet(name, PASSPHRASE)
        wallet.new("hd")
        wallet_list.append(wallet)

    # 2. restore wallet
    w = Wallet.restore("test5", PASSPHRASE, "ordinary mandate edit father snack mesh history identify print borrow skate unhappy cattle tiny first")
    assert len(w.list_address("transfer")["addresses"]) == 0
    wallet_list.append(w)
    w.create_address("transfer")
    w.create_address("transfer")
    w.create_address("staking")
    assert len(w.list_pub_key()) == 2
    assert len(w.list_address("transfer")["addresses"]) == 2
    assert len(w.list_address("staking")["addresses"]) == 1

    #3. check the wallet
    wallet_names = Wallet.list()
    assert sorted(wallet_names) == ["test1", "test2", "test3", "test4", "test5"]

    # 4. export wallet
    export_result = Wallet.export_without_file(wallet_list)
    write_wallet_info_to_file(wallet_list)
    export2file_result = Wallet.export_with_file()
    assert export_result == export2file_result

    #5. delete wallet
    delete_all_wallet()

    #6. import wallet
    Wallet.import_from_file()
    wallet_names = Wallet.list()
    assert sorted(wallet_names) == [w.name for w in wallet_list]
    assert len(w.list_address("transfer")["addresses"]) == 2
    assert len(w.list_address("staking")["addresses"]) == 1



@pytest.mark.zerofee
def test_address():
    delete_all_wallet()
    w1 = Wallet("test-address-1", PASSPHRASE)
    w1.new("hd")
    w2 = Wallet("test-address-2", PASSPHRASE)
    w2.new("basic")
    wallets = [w1, w2]
    for wallet in wallets:
        wallet.create_address("transfer")
        wallet.create_address("transfer")
        wallet.create_address("staking")
        wallet.create_address("staking")
    for wallet in wallets:
        assert len(wallet.list_address("transfer")["addresses"]) == 2
        assert len(wallet.list_address("staking")["addresses"]) == 2
        assert len(wallet.list_pub_key("transfer")) == 2
        assert len(wallet.list_pub_key("staking")) == 2
    wallet_names = Wallet.list()
    assert sorted(wallet_names) == ["test-address-1", "test-address-2"]

@pytest.mark.zerofee
def test_wallet_restore_basic():
    delete_all_wallet()
    wallet = Wallet("test", PASSPHRASE)
    wallet.new("basic")
    private_view_key = wallet.view_key(private = True)
    wallet_basic = Wallet.restore_basic("test-basic", PASSPHRASE, private_view_key)
    assert wallet.view_key() == wallet_basic.view_key()


def init_wallet():
    m = "brick seed fatigue flee earn rural decline switch number cause wheat employ unknown betray tray"
    wallet_sender = Wallet.restore("Default", PASSPHRASE, m)
    wallet_sender.create_address("staking")
    wallet_sender.create_address("staking")

    # create test wallet
    wallet_receiver = Wallet("receiver", PASSPHRASE)
    wallet_receiver.new("basic")

    # create a mock hw wallet
    wallet_hw = Wallet("hw", PASSPHRASE)
    wallet_hw.new("hw")
    return wallet_sender, wallet_receiver, wallet_hw



def withdraw_transactions(wallet, staking_address):
    # test withdraw all unbounded
    tx = Transaction(wallet)
    tx.withdraw(staking_address, wallet.create_address())
    i = 0
    while i < 30:
        wallet.sync()
        balance = wallet.balance
        if balance["available"] > 0:
            break
        time.sleep(1)
    assert balance["available"] == 500000000000000000

def deposit_to_self_address_transaction(wallet, staking_address, amount_cro):
    wallet_balance_begin = wallet.balance
    tx = Transaction(wallet)
    tx_id = tx.deposit(staking_address, amount_cro)
    time.sleep(3)
    wallet.sync()
    t = 0
    find_tx = False
    while t < 30 and not find_tx:
        time.sleep(1)
        wallet.sync()
        for tx_info in tx.history:
            if tx_info["tx_id"] == tx_id:
                find_tx = True
                assert tx_info["tx_type"] == "Deposit"
                assert tx_info["amount"] == amount_cro * CRO
                break
    wallet_balance_end = wallet.balance
    assert wallet_balance_begin["available"] == wallet_balance_end["available"] + amount_cro * CRO

def transfer_to_other_wallet(wallet_sender, wallet_receiver, amount_cro, sender_hardware=None, receiver_hardware=None):
    balance_sender_begin = wallet_sender.balance
    balance_receiver_begin = wallet_receiver.balance
    tx = Transaction(wallet_sender, sender_hardware)
    view_keys = [wallet_receiver.view_key()]
    tx.transfer(wallet_receiver.create_address("transfer", receiver_hardware), amount_cro, view_keys=view_keys)
    balance_sender = wallet_sender.balance
    assert balance_sender["pending"] > 0
    assert balance_sender["total"] == balance_sender_begin["total"] - amount_cro * CRO
    t = 0
    while t < 30 and balance_sender["pending"] > 0:
        time.sleep(1)
        wallet_sender.sync(enable_fast_forward=False)
        balance_sender = wallet_sender.balance
        t += 1
    wallet_receiver.sync(enable_fast_forward=False)
    balance_receiver = wallet_receiver.balance
    assert balance_sender["total"] == balance_sender_begin["total"] - amount_cro * CRO
    assert balance_receiver["total"] == balance_receiver_begin["total"] + amount_cro * CRO

@pytest.mark.zerofee
def test_transaction():
    os.environ['CRYPTO_CLIENT_TENDERMINT'] = 'ws://localhost:26667/websocket'
    wallet_sender, wallet_receiver, wallet_hw = init_wallet()
    # 1. withraw all balance from staking address
    self_staking_address = "0x5e7e1e79d80b861a94598c721598951098dd3825"
    withdraw_transactions(wallet_sender, self_staking_address)
    # 2. test deposit to self address
    deposit_to_self_address_transaction(wallet_sender, self_staking_address, 10000)
    # 3. test transfer to other wallet
    transfer_to_other_wallet(wallet_sender, wallet_receiver, 10000)
    # 4. test mock hw wallet
    transfer_to_other_wallet(wallet_sender, wallet_hw, 10000, receiver_hardware="mock")
    transfer_to_other_wallet(wallet_hw, wallet_sender, 5000, sender_hardware="mock")




