#!/usr/bin/env python3
import os
import time
from chainrpc import RPC
from chainbot import SigningKey
from common import UnixStreamXMLRPCClient, wait_for_validators, wait_for_port, wait_for_blocks, stop_node, wait_for_tx

'''
three node, 1/3 voting power each.
target node: node2
target node mnemonic.
configs:
- missed_block_threshold
- jail_duration

procedure:
- restore node2 wallet on node0
- stop node2
- wait for missed_block_threshold blocks
- check punishment state on the first staking address
- start node2
- wait for node2 port
- do unjail, expect failure.
- wait until jail_time + jail_duration
- do unjail
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
time.sleep(3)
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
rpc.staking.join(
    'node0',
    SigningKey(VALIDATOR_SEED).pub_key_base64(),
    bonded_staking
)

wait_for_blocks(rpc, 3)
assert len(rpc.chain.validators()['validators']) == 2

# start node1
supervisor.supervisor.startProcessGroup('node1')
wait_for_port(BASE_PORT + 10 + 9)

wait_for_blocks(rpc, 13)
punishment = rpc.staking.state(bonded_staking)['punishment']
print('punishment', punishment)
assert punishment['kind'] == 'ByzantineFault'
