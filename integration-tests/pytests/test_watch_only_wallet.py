import time
from chainrpc import RPC
from uuid import uuid1

rpc = RPC()


def test_watch_only_wallet(addresses):
    '''
    - create temp wallet with unique name
    - read view key and transfer address, then delete it
    - recover watch-only wallet with above keys
    - transfer coins from default wallet into the watch-only wallet
    - sync the wallet-only wallet and check the balance
    '''
    name = str(uuid1())
    print('name', name)

    enckey, _ = rpc.wallet.create(name)
    view_key_pub = rpc.wallet.view_key(name, enckey=enckey)
    view_key_priv = rpc.wallet.view_key(name, private=True, enckey=enckey)
    transfer_pubkey = rpc.wallet.list_pubkey(name, enckey=enckey)[0]
    transfer_addr = rpc.address.list(name, type='transfer', enckey=enckey)[0]
    rpc.wallet.delete(name)

    enckey = rpc.wallet.restore_basic(view_key_priv, name=name)
    assert rpc.wallet.view_key(name, enckey=enckey) == view_key_pub

    assert rpc.address.create_watch(
        transfer_pubkey,
        name=name,
        type='transfer',
        enckey=enckey
    ) == transfer_addr

    amount = 10000000
    rpc.wallet.send(transfer_addr, amount, view_keys=[view_key_pub])
    time.sleep(1)  # wait for the block to pop up, FIXME do it more gracefully
    rpc.wallet.sync()
    rpc.wallet.sync(name, enckey=enckey)
    assert int(rpc.wallet.balance(name, enckey=enckey)["total"]) == amount
    assert int(rpc.wallet.balance(name, enckey=enckey)["available"]) == amount
