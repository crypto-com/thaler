from uuid import uuid1

import pytest
from chainrpc import RPC
from .common import wait_for_tx, wait_for_blocktime

rpc = RPC()


@pytest.mark.zerofee
def test_pending_tx(addresses):
    '''
    For this test, we need a clean slate wallet, so we can't use the default wallet.

    prepare test wallet
    - create wallet with unique name
    - create two transfer addresses
    - transfer coins from default wallet to transfer1
    - sync

    test internal transfer tx
    - send coins to transfer2
    - check balance
    - sync
    - check balance again

    outgoing transfer tx
    - create unique wallet, and transfer address
    - transfer coins to it
    - check balance
    - sync
    - check balance again

    deposit tx
    - create staking address
    - deposit coins into staking address, using above transfer txid and index 1.
    - check balance
    - sync
    - check balance again

    withdraw tx
    - unbound and wait for unbound wait period
    - withdraw_all_unbonded from staking address
    - check balance
    - sync
    - check balance again
    '''
    # prepare test wallet
    name = str(uuid1())
    enckey, _ = rpc.wallet.create(name=name)
    viewkey = rpc.wallet.view_key(name=name, enckey=enckey)
    transfer1 = rpc.address.create(name=name, type='transfer', enckey=enckey)
    transfer2 = rpc.address.create(name=name, type='transfer', enckey=enckey)
    wait_for_tx(rpc, rpc.wallet.send(transfer1, 1000000000, view_keys=[viewkey]))
    rpc.wallet.sync(name=name, enckey=enckey)

    # test internal transfer tx
    txid = rpc.wallet.send(transfer2, 100000000, name=name, enckey=enckey)
    assert rpc.wallet.balance(name=name, enckey=enckey) == {
        'total': '900000000',
        'available': '0',
        'pending': '900000000',
    }
    wait_for_tx(rpc, txid)
    rpc.wallet.sync(name=name, enckey=enckey)
    assert rpc.wallet.balance(name=name, enckey=enckey) == {
        'total': '1000000000',
        'available': '1000000000',
        'pending': '0',
    }

    # test outgoing transfer tx
    name2 = str(uuid1())
    enckey2, _ = rpc.wallet.create(name=name2)
    target = rpc.address.create(name=name2, type='transfer', enckey=enckey2)
    txid = rpc.wallet.send(target, 100000000, name=name, enckey=enckey)
    # assuming select the bigger utxo available.
    assert rpc.wallet.balance(name=name, enckey=enckey) == {
        'total': '900000000',
        'available': '100000000',
        'pending': '800000000',
    }
    wait_for_tx(rpc, txid)
    rpc.wallet.sync(name=name, enckey=enckey)
    assert rpc.wallet.balance(name=name, enckey=enckey) == {
        'total': '900000000',
        'available': '900000000',
        'pending': '0',
    }

    # test deposit tx
    staking = rpc.address.create(type='staking', name=name, enckey=enckey)
    txid = rpc.staking.deposit(staking, [{'id': txid, 'index': 1}], name=name, enckey=enckey)
    # assuming select the bigger utxo available.
    assert rpc.wallet.balance(name=name, enckey=enckey) == {
        'total': '100000000',
        'available': '100000000',
        'pending': '0',
    }
    wait_for_tx(rpc, txid)
    rpc.wallet.sync(name=name, enckey=enckey)
    assert rpc.wallet.balance(name=name, enckey=enckey) == {
        'total': '100000000',
        'available': '100000000',
        'pending': '0',
    }

    # test withdraw tx
    wait_for_tx(rpc, rpc.staking.unbond(staking, 800000000, name=name, enckey=enckey))
    wait_for_blocktime(rpc, rpc.staking.state(staking)['unbonded_from'])
    txid = rpc.staking.withdraw_all_unbonded(staking, transfer1, name=name, enckey=enckey)
    assert rpc.wallet.balance(name=name, enckey=enckey) == {
        'total': '900000000',
        'available': '100000000',
        'pending': '800000000',
    }
    wait_for_tx(rpc, txid)
    rpc.wallet.sync(name=name, enckey=enckey)
    assert rpc.wallet.balance(name=name, enckey=enckey) == {
        'total': '900000000',
        'available': '900000000',
        'pending': '0',
    }
