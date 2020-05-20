#!/usr/bin/env python3
import os
import math
from common import get_rpc, UnixStreamXMLRPCClient, wait_for_blocks, stop_node, wait_for_blocktime, wait_for_port, latest_block_time

'''
wait for first reward distribution (the second block)
check reward amount

wait for 5 blocks for byzantine fault detected
check jail status and slashing

wait for reward period for second reward distribution
check jailed node no reward
check slashing is added into reward amount
'''


def monetary_expansion(S, tau):
    period = 10
    Y = 365 * 24 * 60 * 60
    R = 0.45 * math.exp(-S / tau)
    N = int(S * (math.pow(1 + R, period / Y) - 1))
    return N - N % 10000


BASE_PORT = int(os.environ.get('BASE_PORT', 26650))
supervisor = UnixStreamXMLRPCClient('data/supervisor.sock')
wait_for_port(BASE_PORT + 20 + 7)

rpc = get_rpc()
rpc2 = get_rpc(2)
init_bonded = 90000000000000000

os.environ['ENCKEY'] = rpc.wallet.enckey()
bonded_staking = rpc.address.list()[0]

wait_for_blocks(rpc, 2, height=0)

# first reward distribution
# minted = 6978080000
minted = monetary_expansion(init_bonded * 2, 145000000000000000)

state = rpc.chain.staking(bonded_staking, height=2)
assert int(state['bonded']) == init_bonded + minted // 2

enckey2 = rpc2.wallet.enckey()
bonded_staking2 = rpc2.address.list(enckey=enckey2)[0]

state = rpc.chain.staking(bonded_staking2, height=2)
bonded_rewarded = init_bonded + minted // 2
last_bonded = int(state['bonded'])
block_time = latest_block_time(rpc)

if last_bonded == bonded_rewarded:
    # wait for it to get jailed and slashed later
    wait_for_blocks(rpc, 5)

    # jailed and slashed
    slashed = int(last_bonded * 0.2)
    state = rpc.chain.staking(bonded_staking2)
    assert int(state['bonded']) == last_bonded - slashed, 'incorrect bonded: %s' % state['bonded']
    last_bonded = int(state['bonded'])
else:
    # already jailed
    slashed = int(init_bonded * 0.2)
    assert last_bonded == bonded_rewarded - slashed, 'incorrect bonded: %s' % last_bonded

assert state['validator']['jailed_until'] is not None
stop_node(supervisor, 'node1')

# wait for reward period, for second reward distribution
wait_for_blocktime(rpc, block_time + 10)
# minted = 6182420000
minted = monetary_expansion(bonded_rewarded, int(145000000000000000 * 0.99986))

state = rpc.chain.staking(bonded_staking2)
assert int(state['bonded']) == last_bonded, 'jailed node don\'t get rewarded'

state = rpc.chain.staking(bonded_staking)
assert int(state['bonded']) == bonded_rewarded + minted + slashed
