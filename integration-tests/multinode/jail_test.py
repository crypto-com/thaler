#!/usr/bin/env python3
import os
import time
from chainrpc import RPC
from chainbot import SigningKey
from common import UnixStreamXMLRPCClient, wait_for_validators, wait_for_port, wait_for_blocks, wait_for_tx, wait_for_blocktime, stop_node

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
TARGET_NODE = 'node2'
TARGET_NODE_MNEMONIC = 'symptom labor zone shrug chicken bargain hood define tornado mass inquiry rural step color guitar'
TARGET_NODE_VALIDATOR_SEED = '5c1b9c06ae7485cd0f9d75819f964db3b1306ebd397f5bbdc1dd386a32b7c1c0'
MISSED_BLOCK_THRESHOLD = 10
JAIL_DURATION = 10
BASE_PORT = int(os.environ.get('BASE_PORT', 25560))
TARGET_PORT = BASE_PORT + 2 * 10

supervisor = UnixStreamXMLRPCClient('data/supervisor.sock')
rpc = RPC(BASE_PORT)

# wait for 3 validators online
print('Wait for 3 validators online')
wait_for_validators(rpc, 3)

enckey = rpc.wallet.restore(TARGET_NODE_MNEMONIC, name='target')

print('Stop', TARGET_NODE)
time.sleep(5)  # FIXME, remove after adr-001 implemented
stop_node(supervisor, TARGET_NODE)

print('Waiting for', MISSED_BLOCK_THRESHOLD + 3, 'blocks')
wait_for_blocks(rpc, MISSED_BLOCK_THRESHOLD + 3)

assert len(rpc.chain.validators()['validators']) == 2

addr = rpc.address.list(enckey=enckey, name='target')[0]
punishment = rpc.staking.state(addr)['punishment']
print('punishment', punishment)
assert punishment['kind'] == 'NonLive'
print('slash amount', punishment['slash_amount'])

print('Starting', TARGET_NODE)
supervisor.supervisor.startProcessGroup(TARGET_NODE)
wait_for_port(TARGET_PORT + 9)
print('Started', TARGET_NODE)

jailed_until = punishment['jailed_until']
print('Wait until jailed_until:', jailed_until)
wait_for_blocktime(rpc, jailed_until)

print('Unjail', TARGET_NODE)
txid = rpc.staking.unjail(addr, name='target', enckey=enckey)

print('Wait for transaction', txid)
wait_for_tx(rpc, txid)

print('Join', TARGET_NODE)
txid = rpc.staking.join(
    TARGET_NODE,
    SigningKey(TARGET_NODE_VALIDATOR_SEED).pub_key_base64(),
    addr,
    enckey=enckey,
    name='target',
)

print('Wait for transaction', txid)
wait_for_tx(rpc, txid)

print('Wait 3 blocks for validators to take effect')
wait_for_blocks(rpc, 3)

assert len(rpc.chain.validators()['validators']) == 3
