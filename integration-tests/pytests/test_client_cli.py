import json
import pytest
import os
import time
from client_cli import Wallet, Transaction

PASSPHRASE = "123456"


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
    wallet_list.append(w)

    #3. check the wallet
    wallet_names = Wallet.list()
    assert sorted(wallet_names) == ["test1", "test2", "test3", "test4", "test5"]

    #4. export wallet
    export_result = Wallet.export_without_file(wallet_list)
    write_wallet_info_to_file(wallet_list)
    export2file_result = Wallet.export_with_file()
    assert export_result == export2file_result

    #5. delete wallet
    delete_all_wallet()

    #6. import wallet
    Wallet.import_from_file()
    _wallet_names = Wallet.list()
    # TODO: fix import from file bug,  wallet_names should be ["test1", ..., "test5"]
    # assert sorted(wallet_names) == [w.name for w in wallet_list]


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
    return wallet_sender, wallet_receiver

@pytest.mark.zerofee
def test_transactions():
    os.environ['CRYPTO_CLIENT_TENDERMINT'] = 'ws://localhost:26667/websocket'
    wallet_sender, _wallet_receiver = init_wallet()
    # test withdraw all unbounded
    tx = Transaction(wallet_sender)
    staking_address = "0x5e7e1e79d80b861a94598c721598951098dd3825"
    tx.withdraw(staking_address, wallet_sender.create_address())
    i = 0
    while i < 30:
        wallet_sender.sync()
        balance = wallet_sender.balance()
        if balance["available"] >0:
            break
        time.sleep(1)
        print(".", end='')
        if i % 10 == 0:
            print("\n", balance)
        i += 1
    assert balance["available"] == 500000000000000000
