from datetime import datetime
import time
import iso8601


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
