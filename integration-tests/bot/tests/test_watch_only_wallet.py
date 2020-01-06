import time
from chainrpc import RPC
from uuid import uuid1

rpc = RPC()


def test_watch_only_wallet(addresses):
    name = str(uuid1())
    print('name', name)
    assert rpc.wallet.create(name) == name

    view_key_pub = rpc.wallet.view_key(name)
    view_key_priv = rpc.wallet.view_key(name, private=True)
    transfer_pubkey = rpc.wallet.list_pubkey(name)[0]
    transfer_addr = rpc.address.list(name, type='transfer')[0]

    name = 'watch_' + name
    assert rpc.wallet.restore_basic(view_key_priv, name=name) == name
    assert rpc.wallet.view_key(name) == view_key_pub

    assert rpc.address.create_watch(transfer_pubkey, name=name, type='transfer') == transfer_addr

    amount = 10000000
    rpc.wallet.send(transfer_addr, amount, view_keys=[view_key_pub])
    time.sleep(1)  # wait the block to pop up
    rpc.wallet.sync()
    rpc.wallet.sync(name)
    assert int(rpc.wallet.balance(name)["total"])== amount
    assert int(rpc.wallet.balance(name)["available"])== amount
