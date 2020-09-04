#!/usr/bin/env python3
import os
from pathlib import Path
import json
from chainbot import SigningKey, node_key
from common import (
    get_rpc, UnixStreamXMLRPCClient, wait_for_validators,
    wait_for_port, wait_for_blocks, wait_for_tx,
    stop_node, wait_for_blocktime, latest_block_time
)

'''
three node, 1/3 voting power each.
target node: node2
target node mnemonic.
configs:
- missed_block_threshold
- jail_duration

procedure:
- unbond and re-join
 - unbond
 - check number of validators 2
 - withdraw and deposit
 - restart node2 with a new validator key
 - re-join
 - check number of validators 3

- non-live and re-join with new validator key
 - restore node2 wallet on node0
 - stop node2
 - wait for missed_block_threshold blocks to make non-live fault
 - check punishment state on the staking address
 - start node2 with the new validator key
 - re-join with the new validator key
 - check number of validators: 3

- non-live and wait for cleanup
 - stop node2
 - wait for missed_block_threshold blocks to make non-live fault again
 - check punishment state on the staking address
 - wait for unbonding period
 - check node2 validator record is cleaned up
'''

# keep these values same as jail_cluster.json
TARGET_NODE = 'node2'
TARGET_NODE_MNEMONIC = 'symptom labor zone shrug chicken bargain hood define tornado mass inquiry rural step color guitar'
TARGET_NODE_VALIDATOR_SEED = '5c1b9c06ae7485cd0f9d75819f964db3b1306ebd397f5bbdc1dd386a32b7c1c0'
NEW_VALIDATOR_SEED = '5c1b9c06ae7485cd0f9d75819f964db3b1306ebd397f5bbdc1dd386a32b7c1c1'
MISSED_BLOCK_THRESHOLD = 5
JAIL_DURATION = 10
BASE_PORT = int(os.environ.get('BASE_PORT', 26650))
TARGET_PORT = BASE_PORT + 2 * 10

supervisor = UnixStreamXMLRPCClient('data/supervisor.sock')
rpc = get_rpc()
# wait for at least one block generated
wait_for_blocks(rpc, 1, height=0)

# wait for 3 validators online
print('Wait for 3 validators online')
wait_for_validators(rpc, 3)

enckey = rpc.wallet.restore(TARGET_NODE_MNEMONIC, name='target')
addr = rpc.address.list(enckey=enckey, name='target')[0]
state = rpc.staking.state(addr, name='target')

############## unbond and re-join ##################

rpc.wallet.sync(enckey=enckey, name='target')
txid = rpc.staking.unbond(addr, int(state['bonded']) - 100000000 + 1, enckey=enckey, name='target')

print('Wait for tx and 3 blocks')
wait_for_blocks(rpc, 3)
wait_for_tx(rpc, txid)
rpc.wallet.sync(enckey=enckey, name='target')

assert len(rpc.chain.validators()['validators']) == 2

unbonded_from = rpc.staking.state(addr, name='target')['unbonded_from']
print('Wait until unbonded_from', unbonded_from)
wait_for_blocktime(rpc, unbonded_from)

print('Withdraw unbonded', addr)
transfer = rpc.address.list(enckey=enckey, type='transfer', name='target')[0]
txid = rpc.staking.withdraw_all_unbonded(
    addr, transfer, enckey=enckey, name='target',
    # test fee calculation
    view_keys=[
        rpc.wallet.view_key(enckey=enckey, name='target'),
        # view key of node1
        rpc.wallet.view_key(enckey=rpc.wallet.enckey()),
    ]
)

print('Wait for transaction', txid)
wait_for_tx(rpc, txid)
rpc.wallet.sync(enckey=enckey, name='target')

print('Balance', rpc.wallet.balance(enckey=enckey, name='target'))
print('UtxO', rpc.wallet.utxo(enckey=enckey, name='target'))

print('Deposit bonded', txid, addr)
txid = rpc.staking.deposit(addr, [{'id': txid, 'index': 0}], enckey=enckey, name='target')

print('Wait for transaction', txid)
wait_for_tx(rpc, txid)
rpc.wallet.sync(enckey=enckey, name='target')

print('Bonded state:', rpc.staking.state(addr, name='target'))

print('Join node0')
txid = rpc.staking.join(
    TARGET_NODE,
    SigningKey(TARGET_NODE_VALIDATOR_SEED).pub_key_base64(),
    addr,
    rpc.staking.gen_keypackage(),
    enckey=enckey,
    name='target',
)

print('Wait for transaction', txid)
wait_for_tx(rpc, txid)

print('Wait for validator set to take effect')
wait_for_blocks(rpc, 3)

assert len(rpc.chain.validators()['validators']) == 3

############## non-live and re-join with new validator key ##################

print('Stop', TARGET_NODE)
stop_node(supervisor, TARGET_NODE)

print('Waiting for', MISSED_BLOCK_THRESHOLD+1, 'blocks')
wait_for_blocks(rpc, MISSED_BLOCK_THRESHOLD+1)

# assert len(rpc.chain.validators()['validators']) == 2

rpc.wallet.sync(enckey=enckey, name='target')
state = rpc.staking.state(addr, name='target')
print('joinstate', state)
punishment = state['last_slash']
print('punishment', punishment)
assert punishment['kind'] == 'NonLive'
print('slash amount', punishment['amount'])
if state['node_meta']:
    jailed_until = state['node_meta']['CouncilNode']['jailed_until']
    assert jailed_until is None, 'NonLive fault is not jailed'
else:
    print('node is cleaned up')

print('Start node2 with new validator key')
json.dump(node_key(NEW_VALIDATOR_SEED),
          open('./data/%s/tendermint/priv_validator_key.json' % TARGET_NODE, 'w'),
          indent=4)
print('Starting', TARGET_NODE)
supervisor.supervisor.startProcessGroup(TARGET_NODE)
wait_for_port(TARGET_PORT + 7)
print('Started', TARGET_NODE)

print('Join', TARGET_NODE)
txid = rpc.staking.join(
    TARGET_NODE,
    SigningKey(NEW_VALIDATOR_SEED).pub_key_base64(),
    addr,
    rpc.staking.gen_keypackage(),
    enckey=enckey,
    name='target',
)

print('Wait for transaction', txid)
wait_for_tx(rpc, txid)

print('Wait 3 blocks for validators to take effect')
wait_for_blocks(rpc, 3)

assert len(rpc.chain.validators()['validators']) == 3

############## non-live and wait for cleanup ##################

print('Stop', TARGET_NODE)
stop_node(supervisor, TARGET_NODE)

print('Waiting for', MISSED_BLOCK_THRESHOLD + 3, 'blocks')
wait_for_blocks(rpc, MISSED_BLOCK_THRESHOLD + 3)

assert len(rpc.chain.validators()['validators']) == 2

rpc.wallet.sync(enckey=enckey, name='target')
print('state before cleanup', rpc.staking.state(addr, name='target'))

wait_for_blocktime(rpc, latest_block_time(rpc) + 18)
rpc.wallet.sync(enckey=enckey, name='target')
state = rpc.staking.state(addr, name='target')
print('state', state)
assert state.get('node_meta') is None
