import json
import pytest
import os
import time
from client_cli import Wallet, Transaction, run

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

def test_cert_expiration():
    if os.environ.get("BUILD_MODE", "sgx") == "sgx":
        cmd = ["test_cert_expiration", "26651", "202"]
        run(cmd)

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
    wallet_1 = Wallet.restore("Default", PASSPHRASE, m)
    wallet_1.create_address("staking")
    wallet_1.create_address("staking")

    # create test wallet
    wallet_2 = Wallet("test-2", PASSPHRASE)
    wallet_2.new("basic")

    wallet_3 = Wallet("test-3", PASSPHRASE)
    wallet_3.new("basic")

    # create a mock hw wallet
    wallet_hw = Wallet("hw", PASSPHRASE)
    wallet_hw.new("hw", "mock")


def deposit_transaction(wallet, staking_address, amount_cro):
    staking_state_before = wallet.state(staking_address)
    wallet_balance_begin = wallet.balance
    tx = Transaction(wallet)
    tx.deposit(staking_address, amount_cro)
    time.sleep(3)
    wallet.sync()
    wallet_balance_end = wallet.balance
    assert wallet_balance_begin["available"] == wallet_balance_end["available"] + amount_cro * CRO
    h = tx.history[-1]
    assert amount_cro*CRO == h["amount"]
    assert "OUT" == h["side"]
    staking_state_after = wallet.state(staking_address)
    assert staking_state_before['bonded'] + amount_cro*CRO == staking_state_after["bonded"]

def unbounded_transaction(wallet, staking_address, amount_cro):
    tx = Transaction(wallet)
    tx.unbond(staking_address, amount_cro)
    time.sleep(3)
    wallet.sync()


def withdraw_transactions(wallet, staking_address, transfer_address=None, view_keys=[]):
    tx = Transaction(wallet)
    transfer_address = transfer_address or wallet.create_address()
    tx.withdraw(staking_address, transfer_address, view_keys=view_keys)
    i = 0
    while i < 30:
        wallet.sync()
        balance = wallet.balance
        if balance["available"] > 0:
            break
        time.sleep(1)



def transfer_transaction(wallet_sender, wallet_receiver, amount_cro, view_keys=[]):
    balance_sender_begin = wallet_sender.balance
    balance_receiver_begin = wallet_receiver.balance
    tx = Transaction(wallet_sender)
    view_keys.extend([wallet_receiver.view_key()])
    tx.transfer(wallet_receiver.create_address("transfer"), amount_cro, view_keys=view_keys)
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

staking_address_wallet_1 = "0x5e7e1e79d80b861a94598c721598951098dd3825"
wallet_1 = Wallet("Default")
wallet_2 = Wallet("test-2")
wallet_3 = Wallet("test-3")
wallet_hw = Wallet("hw")

@pytest.mark.zerofee
def test_create_wallet():
    os.environ['CRYPTO_CLIENT_TENDERMINT'] = 'ws://localhost:26667/websocket'
    init_wallet()


@pytest.mark.zerofee
def test_withdraw_all_unbonded_from_genesis():
    withdraw_transactions(wallet_1, staking_address_wallet_1)
    balance = wallet_1.balance
    assert balance["available"] == 500000000000000000

@pytest.mark.zerofee
def test_deposit():
    deposit_transaction(wallet_1, staking_address_wallet_1, 10000)

@pytest.mark.zerofee
def test_transfer():
    # test transfer from wallet_1 to wallet_2 with wallet_3's view key
    transfer_transaction(wallet_1, wallet_2, 50000, view_keys=[wallet_3.view_key()])
    # TODO: wallet_3 can view the tx_id, but now can not, because the cmd `client-cli transaction show` uses info from local storage
    # tx_id = Transaction(wallet_2).history[-1]["tx_id"]
    # assert Transaction(wallet_3).can_view_tx(tx_id)

@pytest.mark.zerofee
def test_transfer_hw():
    # test mock hw wallet
    transfer_transaction(wallet_1, wallet_hw, 10000)
    transfer_transaction(wallet_hw, wallet_1, 5000)

@pytest.mark.zerofee
def test_deposit_to_other_wallet():
    # test deposit to other wallet staking address
    wallet_2.sync()
    state1 = wallet_2.state(staking_address_wallet_1)
    deposit_transaction(wallet_2, staking_address_wallet_1, 20000)
    wallet_2.sync()
    state2 = wallet_2.state(staking_address_wallet_1)
    assert state2['bonded'] == state1['bonded'] + 20000*CRO

@pytest.mark.zerofee
def test_withdraw_to_other_wallet():
    # the tx-query cert_validation is 200 (setted in .drone.yaml), check the cert refresh or not
    test_cert_expiration()
    state2 = wallet_2.state(staking_address_wallet_1)
    unbounded_transaction(wallet_1, staking_address_wallet_1, 10000)
    wallet_2.sync()
    state3 = wallet_2.state(staking_address_wallet_1)
    assert state3['bonded'] == state2['bonded'] - 10000*CRO
    assert state3['unbonded'] == state2['unbonded'] + 10000*CRO
    # the time must bigger than the max_age_duration(nano seconds) in tendermint genesis.json
    state3 = wallet_2.state(staking_address_wallet_1)
    time.sleep(10)
    withdraw_transactions(wallet_1, staking_address_wallet_1, wallet_2.create_address("transfer"), view_keys = [wallet_1.view_key(), wallet_2.view_key()])
    # check the receiver wallet history
    time.sleep(3)
    wallet_2.sync()
    history = Transaction(wallet_2).history[-1]
    assert history["side"] == "IN"
    assert history["tx_type"] == "Withdraw"
    assert history["amount"] == 10000*CRO
    state4 = wallet_2.state(staking_address_wallet_1)
    # check the staking state of staking_address_wallet_1
    assert state3["unbonded"] - 10000*CRO == state4["unbonded"]
