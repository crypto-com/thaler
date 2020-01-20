import os
import time
import pytest
from chainrpc import RPC


class TestAddresses:
    def __init__(self, staking, transfer1, transfer2):
        self.staking = staking
        self.transfer1 = transfer1
        self.transfer2 = transfer2


@pytest.fixture
def addresses():
    rpc = RPC()
    enckey = rpc.wallet.enckey()
    os.environ['ENCKEY'] = enckey
    rpc.wallet.sync()
    addrs = TestAddresses(
        rpc.address.list(type='staking')[0],
        rpc.address.list(type='transfer')[0],
        rpc.address.list(type='transfer')[1],
    )

    state = rpc.staking.state(addrs.staking)
    if int(state['unbonded']) > 0:
        rpc.staking.withdraw_all_unbonded(addrs.staking,
                                          addrs.transfer1)
        time.sleep(2)
        rpc.wallet.sync()
        balance = rpc.wallet.balance()
        assert int(balance["total"]) > 0
    else:
        balance = rpc.wallet.balance()
    # wait for the pending amount become available
    loop = 0
    while int(balance["pending"]) != 0 and loop < 60:
        rpc.wallet.sync()
        balance = rpc.wallet.balance()
        time.sleep(1)
        loop += 1
    assert int(balance["available"]) > 0
    return addrs
