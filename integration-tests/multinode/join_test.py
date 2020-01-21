#!/usr/bin/env python3
import os
from chainrpc import RPC
from chainbot import SigningKey
from common import wait_for_tx, wait_for_validators, wait_for_blocks, wait_for_blocktime

'''
three node, equal bonded_coin.

procedure:
- wait for 3 validators online
- unbond part of coin from node0, check validator count not change.
- unbond all of the coins, check validator count decrease
- withdraw and deposit all the coins
- send join request, check validator count increase
'''

BASE_PORT = int(os.environ.get('BASE_PORT', 25560))

# validator seed for node0, keep it same as join_cluster.json
VALIDATOR_SEED = '9f06b6bb885d0143092aad7a6df2f1cae7690fcbfa1edb8727542372085ade8b'

rpc = RPC(BASE_PORT)

print('Wait for 3 validators online')
wait_for_validators(rpc, 3)

enckey = rpc.wallet.enckey()
bonded_staking, _ = rpc.address.list(enckey=enckey)[:2]

rpc.staking.unbond(bonded_staking, 100000000000000000, enckey=enckey)
print('Wait for 3 blocks')
wait_for_blocks(rpc, 3)
rpc.wallet.sync(enckey=enckey)

assert len(rpc.chain.validators()['validators']) == 2

unbonded_from = rpc.staking.state(bonded_staking, enckey=enckey)['unbonded_from']
print('Wait until unbonded_from', unbonded_from)
wait_for_blocktime(rpc, unbonded_from)

print('Withdraw unbonded', bonded_staking)
transfer = rpc.address.list(enckey=enckey, type='transfer')[0]
txid = rpc.staking.withdraw_all_unbonded(bonded_staking, transfer, enckey=enckey)

print('Wait for transaction', txid)
wait_for_tx(rpc, txid)
rpc.wallet.sync(enckey=enckey)

print('Balance', rpc.wallet.balance(enckey=enckey))
print('UtxO', rpc.wallet.utxo(enckey=enckey))

print('Deposit bonded', txid, bonded_staking)
txid = rpc.staking.deposit(bonded_staking, [{'id': txid, 'index': 0}], enckey=enckey)

print('Wait for transaction', txid)
wait_for_tx(rpc, txid)
rpc.wallet.sync(enckey=enckey)

print('Bonded state:', rpc.staking.state(bonded_staking, enckey=enckey))

print('Join node0')
txid = rpc.staking.join(
    'node0',
    SigningKey(VALIDATOR_SEED).pub_key_base64(),
    bonded_staking,
    enckey=enckey
)

print('Wait for transaction', txid)
wait_for_tx(rpc, txid)

print('Wait for validator set to take effect')
wait_for_blocks(rpc, 3)

assert len(rpc.chain.validators()['validators']) == 3
