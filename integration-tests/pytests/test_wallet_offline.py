#!/usr/bin/env python3
import time
import pexpect
import os
import tempfile
import pytest
from chainrpc import RPC
from .common import wait_for_tx, wait_for_blocktime

rpc = RPC()

PASSWD = "123456"
rpc = RPC()

# TODO:it strange that python can not read client-cli output, so deadcode the information
# ./client-cli wallet auth-token -n ${wallet_name}
enckey_offline = "678207f07853b6f2c361989cb3eb31fd15ed0d30da7e01d1e8b50a1f38eb63dd"
# ./client-cli address new -n ${wallet_name} -t transfer
transfer_address_offline = "dcro1ne3l2yxmneg6mfce096424w3dawjmpr6yfjp2tffwd6tn42pp7fst75jua"
# ./client-cli address list-pub-key -n ${wallet_name} -t transfer
transfer_pubkey_offline = "02a732fb6c34812ea5a46547344d63a360e22d0c4815c837af82a09de7b7fd9797"
view_key_offline = "02b4dabfc862b9cb9f86b8d49520023aa0cccb2ad89446577dd0fee7bc946a79a1"
# ./client-cli view-key -p -n ${wallet_name}
priv_view_key_offline = "3aefe25d235b86e2ec25d0a0ee73267e0a0f10f62a4d96df42fc9e7b2f6cbef3"

def create_wallet_offline_wallet(storage_path):
    '''
    - create temp wallet with unique name
    - read view key and transfer address
    return [wallet_name, view_key_priv, transfer_pubkey]
    '''
    os.environ['CRYPTO_CLIENT_STORAGE'] = storage_path
    name = "offline"
    print('offline wallet name:', name)

    cmd = "client-cli wallet restore -n {}".format(name)
    client = pexpect.spawn(cmd)
    time.sleep(1)
    print("send password")
    client.sendline(PASSWD)
    time.sleep(1)
    print("send password")
    client.sendline(PASSWD)
    time.sleep(1)
    print("send mnemonics")
    mnemonics= "ordinary mandate edit father snack mesh history identify print borrow skate unhappy cattle tiny first"
    client.sendline(mnemonics)
    time.sleep(1)
    print("send mnemonics")
    client.sendline(mnemonics)
    # client.interact()
    client.expect(pexpect.EOF)

    print("create offline transfer address")
    cmd = "bash -c 'echo {} | client-cli address new -n {} -t transfer'".format(enckey_offline, name)
    client = pexpect.spawn(cmd)
    #client.interact()
    client.expect(pexpect.EOF)

    print("create offline transfer pubkey")
    cmd = "bash -c 'echo {} | client-cli address list-pub-key -n {} -t transfer'".format(enckey_offline, name)
    client = pexpect.spawn(cmd)
    #client.interact()
    client.expect(pexpect.EOF)
    return name


@pytest.mark.zerofee
def test_wallet_offline():
    print("create offline wallet")
    storage_path = "./data_offline"
    name_offline = create_wallet_offline_wallet(storage_path)

    print("create watchonly wallet")
    name_watchonly = "watchonly"
    print("watchonly wallet name:", name_watchonly)
    enckey_watchonly = rpc.wallet.restore_basic(priv_view_key_offline, name = name_watchonly)
    # 2e856a3f5e3348687094459e8d3f1882a5de9d46187eb55398aa624c81fd9488
    print("enckey watchonly: ", enckey_watchonly)

    print("create transfer address for watchonly wallet")
    transfer_address_watchonly = rpc.address.create_watch(
        transfer_pubkey_offline,
        name=name_watchonly,
        type='transfer',
        enckey=enckey_watchonly,
    )
    assert transfer_address_watchonly == transfer_address_offline

    # first send coin to the offline wallet
    print("send some coin to watchonly wallet")
    amount = 10000000
    time.sleep(2)
    print("transfer address: ", transfer_address_watchonly)
    enckey_default = rpc.wallet.enckey()
    print("default enckey:", enckey_default)
    wait_for_tx(rpc, rpc.wallet.send(to_address=transfer_address_watchonly,
                                     amount=amount,
                                     view_keys=[view_key_offline]))
    rpc.wallet.sync()
    rpc.wallet.sync(name=name_watchonly, enckey = enckey_watchonly)

    balance_watchonly1 = rpc.wallet.balance(name_watchonly, enckey=enckey_watchonly)
    print("balance watchonly", balance_watchonly1)
    assert int(balance_watchonly1["total"]) == amount
    assert int(balance_watchonly1["available"]) == amount

    # create receiver wallet
    print("create receiver wallet")
    name_receiver = "receiver"
    enckey_receiver = rpc.wallet.create(name_receiver)[0]
    print("enckey receiver:", enckey_offline)
    transfer_address_receiver = rpc.address.create(name_receiver, type="transfer", enckey=enckey_receiver)
    view_key_receiver = rpc.wallet.view_key(name_receiver, enckey=enckey_receiver)


    # send coin from watch-only wallet to receiver wallet
    print("build raw transaction")
    view_keys = [view_key_receiver,]
    raw_tx = rpc.staking.build_raw_transfer_tx(to_address = transfer_address_receiver,
                                               amount = "50",
                                               name=name_watchonly,
                                               viewkeys=view_keys,
                                               enckey=enckey_watchonly)
    (_, file_raw_tx) = tempfile.mkstemp(prefix="raw_tx", dir="/tmp", text=True)
    (_, file_signed_tx) = tempfile.mkstemp(prefix="signed_tx", dir="/tmp", text=True)
    with open(file_raw_tx, 'w+') as f:
        f.write(raw_tx)


    # sign the raw_tx
    print("sign raw transaction")
    os.environ['CRYPTO_CLIENT_STORAGE'] = storage_path
    cmd = "bash -c 'echo {} | client-cli transaction sign -n {} --from_file {} --to_file {}'".format(enckey_offline, name_offline, file_raw_tx, file_signed_tx)
    print(cmd)
    client = pexpect.spawn(cmd)
    #client.interact()
    client.expect(pexpect.EOF)

    # read from the file_signed_tx and broadcast
    with open(file_signed_tx, 'r') as f:
        signed = f.read()
        assert len(signed)>0

    print("broadcast raw transaction")
    txid = rpc.staking.broadcast_raw_transfer_tx(signed, name=name_watchonly, enckey=enckey_watchonly)
    wait_for_tx(rpc, txid)

    print("check transfer result")
    rpc.wallet.sync(name_watchonly, enckey=enckey_watchonly)
    balance_watchonly2 = rpc.wallet.balance(name_watchonly, enckey=enckey_watchonly)
    print(balance_watchonly2)
    assert (int(balance_watchonly1["total"]) - int(balance_watchonly2["total"])) <= 50

    rpc.wallet.sync(name_receiver, enckey=enckey_receiver)
    balance_receiver = rpc.wallet.balance(name_receiver, enckey = enckey_receiver)
    print(balance_receiver)
    assert balance_receiver["total"] == "50"



if __name__ == "__main__":
    test_offline_wallet()

