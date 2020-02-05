import os
import time
import pytest
from chainrpc import RPC


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "zerofee: mark test to run only on zerofee env"
    )
    config.addinivalue_line(
        "markers", "withfee: mark test to run only on withfee env"
    )


class TestAddresses:
    def __init__(self, staking1, staking2, transfer1, transfer2):
        self.bonded_staking = staking1
        self.unbonded_staking = staking2
        self.transfer1 = transfer1
        self.transfer2 = transfer2


@pytest.fixture
def addresses():
    rpc = RPC()
    enckey = rpc.wallet.enckey()
    os.environ['ENCKEY'] = enckey
    rpc.wallet.sync()
    stakings = rpc.address.list(type='staking')
    transfers = rpc.address.list(type='transfer')
    addrs = TestAddresses(
        stakings[0], stakings[1],
        transfers[0], transfers[1],
    )

    state = rpc.staking.state(addrs.unbonded_staking)
    if int(state['unbonded']) > 0:
        rpc.staking.withdraw_all_unbonded(
            addrs.unbonded_staking,
            addrs.transfer1
        )
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
