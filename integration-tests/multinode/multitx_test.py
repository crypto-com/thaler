import os
import time
from common import (
    get_rpc, UnixStreamXMLRPCClient, wait_for_validators, stop_node,
    wait_for_tx, latest_block_height, wait_for_blocks
)

'''
Env:
- Two nodes, each with half power

Procedure:
- stop node1
- send tx to node0
- start node1
- repeat above
- test wallet sync
'''


supervisor = UnixStreamXMLRPCClient('data/supervisor.sock')
rpc = get_rpc()
# wait for at least one block generated
wait_for_blocks(rpc, 1, height=0)

print('Wait for 2 validators online')
wait_for_validators(rpc, 2)

os.environ['ENCKEY'] = rpc.wallet.enckey()

print('Prepare node0 transfer addresses')

enckey = rpc.wallet.enckey()
unbonded = rpc.address.list()[1]
transfer1 = rpc.address.list(type='transfer')[0]


txid = rpc.staking.withdraw_all_unbonded(unbonded, transfer1, enckey=enckey)
wait_for_tx(rpc, txid)
rpc.wallet.sync()

addresses = [rpc.address.create(type='transfer') for i in range(10)]
amount = 100000000
for addr in addresses:
    txid = rpc.wallet.send(addr, amount)
    wait_for_tx(rpc, txid)
    rpc.wallet.sync()

print('Stop node1')
stop_node(supervisor, 'node1')

last_height = latest_block_height(rpc)

print('Send multiple tx')
pending_txs = [rpc.wallet.send(transfer1, amount) for _ in addresses]
time.sleep(1)  # Wait a little bit for the tx processing

print('Start node1')
supervisor.supervisor.startProcessGroup('node1')

print('Wait for transaction execution')
for txid in pending_txs:
    wait_for_tx(rpc, txid, timeout=20)

print('Print num_txs in recent blocks')
now_height = latest_block_height(rpc)
for h in range(last_height, now_height+1):
    txs = rpc.chain.block(h)['block']['data']['txs']  or []
    print(len(txs))

print('Check sync ok')
rpc.wallet.sync()
assert rpc.wallet.balance() == {
    'total': '250000000000000000',
    'pending': '0',
    'available': '250000000000000000',
}
