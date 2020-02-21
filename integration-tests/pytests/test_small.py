import pytest
from chainrpc import RPC
from .common import wait_for_tx

rpc = RPC()


@pytest.mark.withfee
def test_deposit_amount(addresses):
    'execute a deposit amount to self, check staking state change'
    bonded1 = int(rpc.staking.state(addresses.unbonded_staking)['bonded'])
    txid = rpc.staking.deposit_amount(addresses.unbonded_staking, 100000000)
    wait_for_tx(rpc, txid)
    rpc.wallet.sync()
    bonded2 = int(rpc.staking.state(addresses.unbonded_staking)['bonded'])
    assert bonded1 + 100000000 == bonded2
