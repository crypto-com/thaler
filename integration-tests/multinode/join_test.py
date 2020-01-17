#!/usr/bin/env python3
import os
import time
from chainrpc import RPC
from chainbot import SigningKey
from common import wait_for_pending, wait_for_validators, wait_for_blocks

'''
three node, node0 has zero bonded coin.

procedure:
- withdraw_all_unbonded from second staking address to first transfer address
- deposit above utxo into first staking address
- call join
'''

BASE_PORT = int(os.environ.get('BASE_PORT', 25560))

# validator seed for node0, keep it same as join_cluster.json
VALIDATOR_SEED = '9f06b6bb885d0143092aad7a6df2f1cae7690fcbfa1edb8727542372085ade8b'

rpc = RPC(BASE_PORT)

print('Wait for 2 validators online')
wait_for_validators(rpc, 2)

enckey = rpc.wallet.enckey()
bonded_staking, unbonded_staking = rpc.address.list(enckey=enckey)[:2]

print('Withdraw unbonded', unbonded_staking)
transfer = rpc.address.list(enckey=enckey, type='transfer')[0]

# FIXME status rpc call deserialization fail when block height = 0.
time.sleep(10)
txid = rpc.staking.withdraw_all_unbonded(unbonded_staking, transfer, enckey=enckey)

print('Wait for wallet to sync...')
wait_for_pending(rpc, enckey)

print('Balance', rpc.wallet.balance(enckey=enckey))
print('UtxO', rpc.wallet.utxo(enckey=enckey))

print('Deposit bonded', txid, bonded_staking)
rpc.staking.deposit(bonded_staking, [{'id': txid, 'index': 0}], enckey=enckey)

print('Wait for wallet to sync...')
wait_for_blocks(rpc, 3)
rpc.wallet.sync(enckey=enckey)

print('Bonded state:', rpc.staking.state(bonded_staking, enckey=enckey))

print('Join node0')
txid = rpc.staking.join(
    'node0',
    SigningKey(VALIDATOR_SEED).pub_key_base64(),
    bonded_staking,
    enckey=enckey
)

print('Wait for 3 blocks')
wait_for_blocks(rpc, 3)
rpc.wallet.sync(enckey=enckey)

print('validators', len(rpc.chain.validators()['validators']))
assert len(rpc.chain.validators()['validators']) == 3
