import os
from datetime import datetime
import time
import iso8601
import weakref


def wait_for_tx(rpc, txid, timeout=10):
    for i in range(timeout):
        time.sleep(1)
        rsp = rpc.chain.tx_search("valid_txs.txid='%s'" % txid)
        if rsp['txs'] and rsp['txs'][0]['tx_result']:
            break
    else:
        raise TimeoutError('Waited too long for the transaction to success: ' + txid)


def wait_for_blocktime(rpc, t):
    print('Wait for block time', t)
    while True:
        time.sleep(1)
        block_time = datetime.timestamp(iso8601.parse_date(rpc.chain.status()['sync_info']['latest_block_time']))
        print('block_time:', block_time)
        if block_time > t:
            break


_rpc_cache = weakref.WeakValueDictionary()


def get_rpc(i=0):
    rpc = _rpc_cache.get(i)
    if rpc is None:
        from chainrpc import RPC
        base_port = int(os.environ.get('BASE_PORT', 26650))
        rpc = RPC(
            os.path.join(os.path.dirname(__file__), '../data/node%d/wallet' % i),
            base_port + 7
        )
        _rpc_cache[i] = rpc
    return rpc
