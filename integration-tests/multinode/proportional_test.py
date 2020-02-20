import os

from chainrpc import RPC
from common import (
    UnixStreamXMLRPCClient, wait_for_validators, wait_for_tx,
    stop_node, latest_block_time, latest_block_height,
    wait_for_port
)

'''
Env:
- Three node, node0 has more than 2/3 power
- Disable generation of empty blocks
- missed_block_threshold set to 5
- slash_wait_period set to 5 seconds

Procedure:
- Query and save staking address of node1 and node2.
- Stop node1 and node2.
- Keep sending tx to generate new blocks, gen missed_block_threshold blocks.
- Check punishment of staking address of node1 and node2.
- Wait slash_wait_period
- Check slash_amount

Compute expected slash_amount:
```
>>> 1/6
0.16666666666666666
>>> import math
>>> math.sqrt(0.166)
0.4074309757492673
>>> (0.407 + 0.407) ** 2
0.662596
>>> 0.662 * 0.1
0.0662
>>> 0.066 * 100000000000000000
6600000000000000
```
'''

BASE_PORT = int(os.environ.get('BASE_PORT', 25560))

wait_for_port(BASE_PORT + 10 + 9)
wait_for_port(BASE_PORT + 20 + 9)

rpc = RPC(BASE_PORT)
rpc1 = RPC(BASE_PORT + 10)
rpc2 = RPC(BASE_PORT + 20)

supervisor = UnixStreamXMLRPCClient('data/supervisor.sock')

print('Wait for 3 validators online')
wait_for_validators(rpc, 3)

# enckey is the same for all default wallets
enckey = rpc.wallet.enckey()

staking1 = rpc1.address.list(enckey=enckey)[0]
staking2 = rpc2.address.list(enckey=enckey)[0]

print('Stop node1 and node2')
stop_node(supervisor, 'node1')
stop_node(supervisor, 'node2')

print('Wait for missed_block_threshold(5) blocks')
height = latest_block_height(rpc)

transfer = rpc.address.list(type='transfer', enckey=enckey)[0]
txid = rpc.staking.withdraw_all_unbonded(
    rpc.address.list(enckey=enckey)[1],
    transfer,
    enckey=enckey,
)
wait_for_tx(rpc, txid)
rpc.wallet.sync(enckey=enckey)

while latest_block_height(rpc) - height <= 5:
    txid = rpc.wallet.send(transfer, 100000000, enckey=enckey)
    wait_for_tx(rpc, txid)
    rpc.wallet.sync(enckey=enckey)

print('Check the punishments')
assert rpc.staking.state(staking1)['punishment']['kind'] == \
    rpc.staking.state(staking2)['punishment']['kind'] == \
    'NonLive'

print('Wait for slash_wait_period(5 seconds)')
begin = latest_block_time(rpc)
while True:
    txid = rpc.wallet.send(transfer, 100000000, enckey=enckey)
    wait_for_tx(rpc, txid)
    rpc.wallet.sync(enckey=enckey)
    if latest_block_time(rpc) - begin > 5:
        break

print('Check slash amount')
assert rpc.staking.state(staking1)['punishment']['slash_amount'] == \
    rpc.staking.state(staking2)['punishment']['slash_amount'] == \
    '6600000000000000'
