#!/usr/bin/env python3
import os
import getpass
import logging
import base64
import binascii
import json
import subprocess
import tempfile


from jsonrpcclient import request
from decouple import config

from chainbinding import RpcBinding

DEBUG_LEVEL = config('HTTP_DEBUG_LEVEL', 0, cast=int)
if DEBUG_LEVEL:
    try:
        import http.client as http_client
    except ImportError:
        # Python 2
        import httplib as http_client
    http_client.HTTPConnection.debuglevel = DEBUG_LEVEL

    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

DEFAULT_WALLET = config('DEFAULT_WALLET', 'Default')
CARGO_TARGET_DIR = config('CARGO_TARGET_DIR', '../target')
MLS_ENCLAVE_PATH = config(
    'MLS_ENCLAVE_PATH',
    os.path.join(CARGO_TARGET_DIR,
                 'x86_64-fortanix-unknown-sgx/debug/mls.sgxs')
)


def get_passphrase():
    phrase = config('PASSPHRASE', None)
    if phrase is None:
        phrase = getpass.getpass('Input passphrase:')
    return phrase


def get_enckey():
    key = config('ENCKEY', None)
    if key is None:
        key = getpass.getpass('Input enckey:')
    return key


def fix_address(addr):
    'fire convert staking addr to int automatically, fix it.'
    if isinstance(addr, int):
        return '0x%040x' % addr
    else:
        return addr


def fix_address_hex(addr):
    'fire convert staking addr to int automatically, fix it.'
    if isinstance(addr, int):
        return '%040x' % addr
    elif addr.startswith('0x'):
        return addr[2:]
    else:
        return addr


class Client:
    def __init__(self, tendermint_port, wallet_directory, network_id, mock_mode):
        self.binding = RpcBinding(
            wallet_directory,
            'ws://127.0.0.1:%d/websocket' % tendermint_port,
            network_id=network_id,
            mock_mode=mock_mode
        )
        self.mock_mode = mock_mode

    def call(self, method, *args, **kwargs):
        params = None
        if args and kwargs:
            params = list(args)
            params.append(kwargs)
        elif args:
            params = list(args)
        elif kwargs:
            params = kwargs
        req = {
            'jsonrpc': '2.0',
            'id': '0',
            'method': method,
            'params': params
        }
        rsp = json.loads(self.binding.call(json.dumps(req)))
        assert 'result' in rsp, rsp['error']
        return rsp['result']


class Address:
    def __init__(self, client):
        self.client = client

    def list(self, name=DEFAULT_WALLET, type='staking', enckey=None):
        '''list addresses
        :param name: Name of the wallet. [default: Default]
        :params type: [staking|transfer]'''
        return self.client.call('wallet_listStakingAddresses' if type == 'staking' else 'wallet_listTransferAddresses', [name, enckey or get_enckey()])

    def create(self, name=DEFAULT_WALLET, type='staking', enckey=None):
        '''Create address
        :param name: Name of the wallet
        :param type: Type of address. [staking|transfer]'''
        type = type.lower()
        assert type in ('staking', 'transfer'), 'invalid type'
        return self.client.call(
            'wallet_createStakingAddress'
            if type == 'staking'
            else 'wallet_createTransferAddress',
            [name, enckey or get_enckey()])

    def create_watch(self, public_key, name=DEFAULT_WALLET, type='staking', enckey=None):
        '''Create watch address for watch only wallet
        :param name: Name of the wallet
        :param type: Type of address. [staking|transfer]
        :param public_key: Public key of the address'''
        type = type.lower()
        assert type in ('staking', 'transfer'), 'invalid type'
        return self.client.call(
            'wallet_createWatchStakingAddress'
            if type == 'staking'
            else 'wallet_createWatchTransferAddress',
            [name, enckey or get_enckey()], public_key)


class Wallet:
    def __init__(self, client):
        self.client = client

    def enckey(self, name=DEFAULT_WALLET):
        '''Get encryption key of wallet
        :param name: Name of the wallet. [default: Default]'''
        return self.client.call('wallet_getEncKey', [name, get_passphrase()])

    def balance(self, name=DEFAULT_WALLET, enckey=None):
        '''Get balance of wallet
        :param name: Name of the wallet. [default: Default]'''
        return self.client.call('wallet_balance', [name, enckey or get_enckey()])

    def list(self):
        return self.client.call('wallet_list')

    def utxo(self, name=DEFAULT_WALLET, enckey=None):
        '''Get UTxO of wallet
        :param name: Name of the wallet. [default: Default]'''
        return self.client.call('wallet_listUTxO', [name, enckey or get_enckey()])

    def create(self, name=DEFAULT_WALLET, type='Basic', passphrase=None):
        '''create wallet
        :param name: Name of the wallet. [defualt: Default]
        :param type: Type of the wallet. [Basic|HD] [default: Basic]
        '''
        return self.client.call('wallet_create', [name, passphrase or get_passphrase()], type)

    def restore(self, mnemonics, name=DEFAULT_WALLET, passphrase=None):
        '''restore wallet
        :param name: Name of the wallet. [defualt: Default]
        :param mnemonics: mnemonics words
        '''
        return self.client.call('wallet_restore', [name, passphrase or get_passphrase()], mnemonics)

    def restore_basic(self, private_view_key, name=DEFAULT_WALLET, passphrase=None):
        '''restore wallet
        :param name: Name of the wallet. [defualt: Default]
        :param private_view_key: hex encoded private view key
        '''
        return self.client.call('wallet_restoreBasic', [name, passphrase or get_passphrase()], private_view_key)

    def delete(self, name=DEFAULT_WALLET, passphrase=None):
        return self.client.call('wallet_delete', [name, passphrase or get_passphrase()])

    def view_key(self, name=DEFAULT_WALLET, private=False, enckey=None):
        return self.client.call(
            'wallet_getViewKey',
            [name, enckey or get_enckey()], private
        )

    def list_pubkey(self, name=DEFAULT_WALLET, enckey=None):
        return self.client.call('wallet_listPublicKeys', [name, enckey or get_enckey()])

    def transactions(self, name=DEFAULT_WALLET, offset=0, limit=100, reversed=False, enckey=None):
        return self.client.call('wallet_transactions', [name, enckey or get_enckey()], offset, limit, reversed)

    def send(self, to_address, amount, name=DEFAULT_WALLET, view_keys=None, enckey=None):
        return self.client.call(
            'wallet_sendToAddress',
            [name, enckey or get_enckey()],
            to_address, str(amount), view_keys or [])

    def sync(self, name=DEFAULT_WALLET, enckey=None):
        return self.client.call('sync', [name, enckey or get_enckey()],{"blocking":True, "reset":False, "do_loop":False})

    def sync_all(self, name=DEFAULT_WALLET, enckey=None):
        return self.client.call('sync', [name, enckey or get_enckey()],{"blocking":True, "reset":True, "do_loop":False})

    def sync_unlock(self, name=DEFAULT_WALLET, enckey=None):
        return self.client.call('sync', [name, enckey or get_enckey()],{"blocking":False, "reset":False, "do_loop":True})

    def sync_stop(self, name=DEFAULT_WALLET, enckey=None):
        return self.client.call('sync_stop', [name, enckey or get_enckey()])

    def build_raw_transfer_tx(self, to_address, amount, name=DEFAULT_WALLET,  enckey=None, viewkeys=[]):
        """
        build a raw transfer tx on watch-only wallet
        :return: unsigned raw transaction info encoded in base64 string
        """
        return self.client.call('wallet_buildRawTransferTransaction', [name, enckey or get_enckey()], to_address, str(amount), viewkeys)

    def broadcast_signed_transfer_tx(self, signed_tx, name=DEFAULT_WALLET, enckey=None):
        """
        send a transfer tx signed by offline wallet
        :return:
        """
        return self.client.call('wallet_broadcastSignedTransferTransaction', [name, enckey or get_enckey()], signed_tx)


class Staking:
    def __init__(self, client):
        self.client = client

    def deposit(self, to_address, inputs, name=DEFAULT_WALLET, enckey=None):
        return self.client.call('staking_depositStake', [name, enckey or get_enckey()], fix_address(to_address), inputs)

    def deposit_amount(self, to_address, amount, name=DEFAULT_WALLET, enckey=None):
        return self.client.call('staking_depositAmountStake', [name, enckey or get_enckey()], fix_address(to_address), str(amount))

    def state(self, address, name=DEFAULT_WALLET):
        return self.client.call('staking_state', name, fix_address(address))

    def unbond(self, address, amount, name=DEFAULT_WALLET, enckey=None):
        return self.client.call('staking_unbondStake', [name, enckey or get_enckey()], fix_address(address), str(amount))

    def withdraw_all_unbonded(self, from_address, to_address, view_keys=None, name=DEFAULT_WALLET, enckey=None):
        return self.client.call(
            'staking_withdrawAllUnbondedStake',
            [name, enckey or get_enckey()],
            fix_address(from_address), to_address, view_keys or []
        )

    def unjail(self, address, name=DEFAULT_WALLET, enckey=None):
        return self.client.call('staking_unjail', [name, enckey or get_enckey()], fix_address(address))

    def join(self, node_name, node_pubkey, node_staking_address, keypackage, name=DEFAULT_WALLET, enckey=None):
        return self.client.call(
            'staking_validatorNodeJoin',
            [name, enckey or get_enckey()],
            node_name,
            node_pubkey,
            fix_address(node_staking_address),
            keypackage
        )

    def build_raw_transfer_tx(self, to_address, amount, name=DEFAULT_WALLET,  enckey=None, viewkeys=[]):
        return self.client.call('wallet_buildRawTransferTx', [name, enckey or get_enckey()], to_address, amount, viewkeys)

    def broadcast_raw_transfer_tx(self, signed_tx, name=DEFAULT_WALLET, enckey=None):
        return self.client.call('wallet_broadcastSignedTransferTx', [name, enckey or get_enckey()], signed_tx)

    def gen_keypackage(self, path=MLS_ENCLAVE_PATH):
        if self.client.mock_mode:
            return ''
        else:
            temp = tempfile.NamedTemporaryFile()
            subprocess.run(["dev-utils", "keypackage", "generate","--path", path, "--output", temp.name])
            value= temp.read().decode('utf-8')
            return value 


class MultiSig:
    def __init__(self, client):
        self.client = client

    def create_address(self, public_keys, self_public_key, required_signatures, name=DEFAULT_WALLET, enckey=None):
        return self.client.call(
            'multiSig_createAddress',
            [name, enckey or get_enckey()],
            public_keys,
            self_public_key,
            required_signatures)

    def new_session(self, message, signer_public_keys, self_public_key, name=DEFAULT_WALLET, enckey=None):
        return self.client.call(
            'multiSig_newSession',
            [name, enckey or get_enckey()],
            message,
            signer_public_keys,
            self_public_key)

    def nonce_commitment(self, session_id, passphrase):
        return self.client.call('multiSig_nonceCommitment', session_id, passphrase)

    def add_nonce_commitment(self, session_id, passphrase, nonce_commitment, public_key):
        return self.client.call('multiSig_addNonceCommitment', session_id, passphrase, nonce_commitment, public_key)

    def nonce(self, session_id, passphrase):
        return self.client.call('multiSig_nonce', session_id, passphrase)

    def add_nonce(self, session_id, passphrase, nonce, public_key):
        return self.client.call('multiSig_addNonce', session_id, passphrase, nonce, public_key)

    def partial_signature(self, session_id, passphrase):
        return self.client.call('multiSig_partialSign', session_id, passphrase)

    def add_partial_signature(self, session_id, passphrase, partial_signature, public_key):
        return self.client.call('multiSig_addPartialSignature', session_id, passphrase, partial_signature, public_key)

    def signature(self, session_id, passphrase):
        return self.client.call('multiSig_signature', session_id, passphrase)

    def broadcast_with_signature(self, session_id, unsigned_transaction, name=DEFAULT_WALLET, enckey=None):
        return self.client.call(
            'multiSig_broadcastWithSignature',
            [name, enckey or get_enckey()],
            session_id,
            unsigned_transaction)


class Blockchain:
    def __init__(self, tendermint_port):
        self.tendermint_http = 'http://127.0.0.1:%d' % tendermint_port

    def call_chain(self, method, *args, **kwargs):
        rsp = request(self.tendermint_http, method, *args, **kwargs)
        return rsp.data.result

    def status(self):
        return self.call_chain('status')

    def info(self):
        return self.call_chain('info')

    def genesis(self):
        return self.call_chain('genesis')

    def unconfirmed_txs(self):
        return self.call_chain('unconfirmed_txs')

    def latest_height(self):
        return self.status()['sync_info']['latest_block_height']

    def validators(self, height=None, page=0, num_per_page=100):
        return self.call_chain('validators', str(height) if height is not None else None, str(page), str(num_per_page))

    def block(self, height='latest'):
        height = height if height != 'latest' else self.latest_height()
        return self.call_chain('block', str(height))

    def block_results(self, height='latest'):
        height = height if height != 'latest' else self.latest_height()
        return self.call_chain('block_results', str(height))

    def chain(self, min_height, max_height='latest'):
        max_height = max_height if max_height != 'latest' else self.latest_height()
        return self.call_chain('blockchain', str(min_height), str(max_height))

    def commit(self, height='latest'):
        height = height if height != 'latest' else self.latest_height()
        return self.call_chain('commit', str(height))

    def query(self, path, data=None, height=None, proof=False):
        return self.call_chain(
            'abci_query', path, fix_address_hex(data),
            str(height) if height is not None else "-1", proof
        )

    def broadcast_tx_commit(self, tx):
        return self.call_chain('broadcast_tx_commit', tx)

    def broadcast_tx_sync(self, tx):
        return self.call_chain('broadcast_tx_sync', tx)

    def broadcast_tx_async(self, tx):
        return self.call_chain('broadcast_tx_async', tx)

    def tx(self, txid, include_proof=False):
        txid = base64.b64encode(binascii.unhexlify(txid)).decode()
        return self.call_chain('tx', txid, include_proof)

    def tx_search(self, query, include_proof=False,
                  page=1, per_page=100, order_by="asc"):
        return self.call_chain(
            'tx_search', query=query, prove=include_proof,
            page=str(page), per_page=str(per_page),
            order_by=order_by
        )

    def staking(self, address, height=None, prove=False):
        import chaincodec
        rsp = self.query("staking", address, height, prove)
        rsp = rsp['response']
        assert rsp['code'] == 0, rsp
        staking = chaincodec.decode(
            'Option<StakedState>',
            bytearray(base64.b64decode(rsp['value']))
        )
        if prove:
            proof = chaincodec.decode(
                'SparseMerkleProof',
                bytearray(base64.b64decode(rsp['proof']['ops'][0]['data']))
            )
            return {
                'staking': staking,
                'proof': proof
            }
        else:
            return staking


class RPC:
    def __init__(self, wallet_directory=None, tendermint_rpc_port=None, network_id=0xab, mock_mode=None):
        if wallet_directory is None:
            wallet_directory = config('WALLET_DIRECTORY')
        if tendermint_rpc_port is None:
            tendermint_rpc_port = config('TENDERMINT_RPC_PORT', 26657)
        if mock_mode is None:
            mock_mode = config('BUILD_MODE', 'sgx') == 'mock'
        client = Client(tendermint_rpc_port, wallet_directory, network_id, mock_mode)
        self.wallet = Wallet(client)
        self.staking = Staking(client)
        self.address = Address(client)
        self.multisig = MultiSig(client)
        self.chain = Blockchain(tendermint_rpc_port)

    def raw_tx(self, inputs, outputs, view_keys):
        return self.wallet.call('transaction_createRaw', inputs, outputs, view_keys)


if __name__ == '__main__':
    import fire
    fire.Fire(RPC)
