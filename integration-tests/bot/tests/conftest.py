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
    rpc.wallet.sync()
    addrs = TestAddresses(
        rpc.address.list(type='staking')[1],
        rpc.address.list(type='transfer')[0],
        rpc.address.list(type='transfer')[1],
    )

    state = rpc.staking.state(addrs.staking)
    if int(state['unbonded']) > 0:
        rpc.staking.withdraw_all_unbonded(addrs.staking,
                                          addrs.transfer1)
        rpc.wallet.sync()
        assert rpc.wallet.balance() > 0
    return addrs
