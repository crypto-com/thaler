import os
import time
from datetime import datetime
import http.client
import socket
import xmlrpc.client
import iso8601
import weakref


def wait_for_port(port, host='127.0.0.1', timeout=40.0):
    start_time = time.perf_counter()
    while True:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                break
        except OSError as ex:
            time.sleep(0.1)
            if time.perf_counter() - start_time >= timeout:
                raise TimeoutError('Waited too long for the port {} on host {} to start accepting '
                                   'connections.'.format(port, host)) from ex


def wait_for_tx(rpc, txid, timeout=10):
    for i in range(timeout):
        time.sleep(1)
        rsp = rpc.chain.tx_search("valid_txs.txid='%s'" % txid)
        if rsp['txs'] and rsp['txs'][0]['tx_result']:
            break
    else:
        raise TimeoutError('Waited too long for the transaction to success: ' + txid)


def wait_for_validators(rpc, count, timeout=10):
    for i in range(timeout):
        n = len(rpc.chain.validators()['validators'])
        print('Checking validators', n)
        if n >= count:
            break
        time.sleep(1)
    else:
        raise TimeoutError('validators still not enough, giveup')


def latest_block_height(rpc):
    return int(rpc.chain.status()['sync_info']['latest_block_height'])


def wait_for_blocks(rpc, n, height=None):
    height = height if height is not None else latest_block_height(rpc)
    while True:
        time.sleep(1)
        delta = latest_block_height(rpc) - height
        if delta >= n:
            break


def stop_node(supervisor, name):
    supervisor.supervisor.stopProcess('%s:%s-%s' % (name, 'tendermint', name))
    supervisor.supervisor.stopProcessGroup(name)


def latest_block_time(rpc):
    return datetime.timestamp(iso8601.parse_date(rpc.chain.status()['sync_info']['latest_block_time']))


def wait_for_blocktime(rpc, t):
    while True:
        time.sleep(1)
        block_time = latest_block_time(rpc)
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


class UnixStreamHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(
            socket.AF_UNIX, socket.SOCK_STREAM
        )
        self.sock.connect(self.host)


class UnixStreamTransport(xmlrpc.client.Transport, object):
    def __init__(self, socket_path):
        self.socket_path = socket_path
        super().__init__()

    def make_connection(self, host):
        return UnixStreamHTTPConnection(self.socket_path)


class UnixStreamXMLRPCClient(xmlrpc.client.ServerProxy):
    'to communicate with supervisord'
    def __init__(self, addr, **kwargs):
        transport = UnixStreamTransport(addr)
        super().__init__(
            "http://", transport=transport, **kwargs
        )
