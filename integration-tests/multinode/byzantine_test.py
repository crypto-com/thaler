#!/usr/bin/env python3
import os
from chainrpc import RPC
from chainbot import SigningKey
from common import UnixStreamXMLRPCClient, wait_for_validators, wait_for_port, wait_for_blocks, stop_node, wait_for_tx

'''
- 3 nodes
- node2 has more than 2/3 voting powers
- node0 and node1 have same validator seed, both have 0 bonded coins initially, only unbonded coins.
- start the nodes, and stop node1 immediately.
- withdraw, deposit and join node0.
- start node1, check node0 punished with byzantine fault.
'''

# keep these values same as jail_cluster.json
VALIDATOR_SEED = '3d96c3c476e463bdcd751c9bf1715b7da37229ac00be33f34496797ca892b68a'
BASE_PORT = int(os.environ.get('BASE_PORT', 25560))
TARGET_PORT = BASE_PORT + 2 * 10

supervisor = UnixStreamXMLRPCClient('data/supervisor.sock')
rpc = RPC(BASE_PORT)

# stop node1
print('Stop node1')
stop_node(supervisor, 'node1')

print('Wait for 1 validators online')
wait_for_validators(rpc, 1)

enckey = rpc.wallet.enckey()
os.environ['ENCKEY'] = enckey
bonded_staking, unbonded_staking = rpc.address.list()[:2]
transfer = rpc.address.list(type='transfer')[0]

txid = rpc.staking.withdraw_all_unbonded(unbonded_staking, transfer)
wait_for_tx(rpc, txid)
rpc.wallet.sync()

txid = rpc.staking.deposit(bonded_staking, [{'id': txid, 'index': 0}])
wait_for_tx(rpc, txid)
rpc.wallet.sync()

wait_for_blocks(rpc, 3)

print('Join node0')
txid = rpc.staking.join(
    'node0',
    SigningKey(VALIDATOR_SEED).pub_key_base64(),
    bonded_staking
)

wait_for_tx(rpc, txid)

wait_for_blocks(rpc, 3)
assert len(rpc.chain.validators()['validators']) == 2

# start node1
supervisor.supervisor.startProcessGroup('node1')
wait_for_port(BASE_PORT + 10 + 9)

wait_for_blocks(rpc, 13)
punishment = rpc.staking.state(bonded_staking)['punishment']
print('punishment', punishment)
assert punishment['kind'] == 'ByzantineFault'
