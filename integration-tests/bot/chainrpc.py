#!/usr/bin/env python3
import getpass
import logging

import fire
from jsonrpcclient import request
from decouple import config

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

BASE_PORT = config('BASE_PORT', 26650, cast=int)
CLIENT_RPC_URL = config('CLIENT_RPC_URL', 'http://127.0.0.1:%d' % (BASE_PORT + 9))
CHAIN_RPC_URL = config('CHAIN_RPC_URL', 'http://127.0.0.1:%d' % (BASE_PORT + 7))
DEFAULT_WALLET = config('DEFAULT_WALLET', 'Default')


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


def call(method, *args, **kwargs):
    rsp = request(CLIENT_RPC_URL, method, *args, **kwargs)
    return rsp.data.result


def call_chain(method, *args):
    rsp = request(CHAIN_RPC_URL, method, *args)
    return rsp.data.result


def fix_address(addr):
    'fire convert staking addr to int automatically, fix it.'
    if isinstance(addr, int):
        return hex(addr)
    else:
        return addr


class Address:
    def list(self, name=DEFAULT_WALLET, type='staking', enckey=None):
        '''list addresses
        :param name: Name of the wallet. [default: Default]
        :params type: [staking|transfer]'''
        return call('wallet_listStakingAddresses' if type == 'staking' else 'wallet_listTransferAddresses', [name, enckey or get_enckey()])

    def create(self, name=DEFAULT_WALLET, type='staking', enckey=None):
        '''Create address
        :param name: Name of the wallet
        :param type: Type of address. [staking|transfer]'''
        type = type.lower()
        assert type in ('staking', 'transfer'), 'invalid type'
        return call(
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
        return call(
            'wallet_createWatchStakingAddress'
            if type == 'staking'
            else 'wallet_createWatchTransferAddress',
            [name, enckey or get_enckey()], public_key)


class Wallet:
    def enckey(self, name=DEFAULT_WALLET):
        '''Get encryption key of wallet
        :param name: Name of the wallet. [default: Default]'''
        return call('wallet_getEncKey', [name, get_passphrase()])

    def balance(self, name=DEFAULT_WALLET, enckey=None):
        '''Get balance of wallet
        :param name: Name of the wallet. [default: Default]'''
        return call('wallet_balance', [name, enckey or get_enckey()])

    def list(self):
        return call('wallet_list')

    def utxo(self, name=DEFAULT_WALLET, enckey=None):
        '''Get UTxO of wallet
        :param name: Name of the wallet. [default: Default]'''
        return call('wallet_listUTxO', [name, enckey or get_enckey()])

    def create(self, name=DEFAULT_WALLET, type='Basic', passphrase=None):
        '''create wallet
        :param name: Name of the wallet. [defualt: Default]
        :param type: Type of the wallet. [Basic|HD] [default: Basic]
        '''
        return call('wallet_create', [name, passphrase or get_passphrase()], type)

    def restore(self, mnemonics, name=DEFAULT_WALLET, passphrase=None):
        '''restore wallet
        :param name: Name of the wallet. [defualt: Default]
        :param mnemonics: mnemonics words
        '''
        return call('wallet_restore', [name, passphrase or get_passphrase()], mnemonics)

    def restore_basic(self, private_view_key, name=DEFAULT_WALLET, passphrase=None):
        '''restore wallet
        :param name: Name of the wallet. [defualt: Default]
        :param private_view_key: hex encoded private view key
        '''
        return call('wallet_restoreBasic', [name, passphrase or get_passphrase()], private_view_key)

    def view_key(self, name=DEFAULT_WALLET, private=False, enckey=None):
        return call(
            'wallet_getViewKey',
            [name, enckey or get_enckey()], private
        )

    def list_pubkey(self, name=DEFAULT_WALLET, enckey=None):
        return call('wallet_listPublicKeys', [name, enckey or get_enckey()])

    def transactions(self, name=DEFAULT_WALLET, offset=0, limit=100, reversed=False, enckey=None):
        return call('wallet_transactions', [name, enckey or get_enckey()], offset, limit, reversed)

    def send(self, to_address, amount, name=DEFAULT_WALLET, view_keys=None, enckey=None):
        return call(
            'wallet_sendToAddress',
            [name, enckey or get_enckey()],
            to_address, str(amount), view_keys or [])

    def sync(self, name=DEFAULT_WALLET, enckey=None):
        return call('sync', [name, enckey or get_enckey()])

    def sync_all(self, name=DEFAULT_WALLET, enckey=None):
        return call('sync_all', [name, enckey or get_enckey()])

    def sync_unlock(self, name=DEFAULT_WALLET, enckey=None):
        return call('sync_unlockWallet', [name, enckey or get_enckey()])

    def sync_stop(self, name=DEFAULT_WALLET, enckey=None):
        return call('sync_stop', [name, enckey or get_enckey()])


class Staking:
    def deposit(self, to_address, inputs, name=DEFAULT_WALLET, enckey=None):
        return call('staking_depositStake', [name, enckey or get_enckey()], fix_address(to_address), inputs)

    def state(self, address, name=DEFAULT_WALLET, enckey=None):
        return call('staking_state', [name, enckey or get_enckey()], fix_address(address))

    def unbond(self, address, amount, name=DEFAULT_WALLET, enckey=None):
        return call('staking_unbondStake', [name, enckey or get_enckey()], fix_address(address), str(amount))

    def withdraw_all_unbonded(self, from_address, to_address, view_keys=None, name=DEFAULT_WALLET, enckey=None):
        return call(
            'staking_withdrawAllUnbondedStake',
            [name, enckey or get_enckey()],
            fix_address(from_address), to_address, view_keys or []
        )

    def unjail(self, address, name=DEFAULT_WALLET, enckey=None):
        return call('staking_unjail', [name, enckey or get_enckey()], fix_address(address))

    def join(self, node_name, node_pubkey, node_staking_address, name=DEFAULT_WALLET, enckey=None):
        return call('staking_validatorNodeJoin', [name, enckey or get_enckey()], node_name, node_pubkey,  fix_address(node_staking_address))


class MultiSig:
    def create_address(self, public_keys, self_public_key, required_signatures, name=DEFAULT_WALLET, enckey=None):
        return call('multiSig_createAddress',
                    [name, enckey or get_enckey()],
                    public_keys,
                    self_public_key,
                    required_signatures)

    def new_session(self, message, signer_public_keys, self_public_key, name=DEFAULT_WALLET, enckey=None):
        return call('multiSig_newSession',
                    [name, enckey or get_enckey()],
                    message,
                    signer_public_keys,
                    self_public_key)

    def nonce_commitment(self, session_id, passphrase):
        return call('multiSig_nonceCommitment', session_id, passphrase)

    def add_nonce_commitment(self, session_id, passphrase, nonce_commitment, public_key):
        return call('multiSig_addNonceCommitment', session_id, passphrase, nonce_commitment, public_key)

    def nonce(self, session_id, passphrase):
        return call('multiSig_nonce', session_id, passphrase)

    def add_nonce(self, session_id, passphrase, nonce, public_key):
        return call('multiSig_addNonce', session_id, passphrase, nonce, public_key)

    def partial_signature(self, session_id, passphrase):
        return call('multiSig_partialSign', session_id, passphrase)

    def add_partial_signature(self, session_id, passphrase, partial_signature, public_key):
        return call('multiSig_addPartialSignature', session_id, passphrase, partial_signature, public_key)

    def signature(self, session_id, passphrase):
        return call('multiSig_signature', session_id, passphrase)

    def broadcast_with_signature(self, session_id, unsigned_transaction, name=DEFAULT_WALLET, enckey=None):
        return call('multiSig_broadcastWithSignature',
                    [name, enckey or get_enckey()],
                    session_id,
                    unsigned_transaction)


class Blockchain:
    def status(self):
        return call_chain('status')

    def info(self):
        return call_chain('info')

    def genesis(self):
        return call_chain('genesis')

    def unconfirmed_txs(self):
        return call_chain('unconfirmed_txs')

    def latest_height(self):
        return self.status()['sync_info']['latest_block_height']

    def validators(self, height=None):
        return call_chain('validators', str(height) if height is not None else None)

    def block(self, height='latest'):
        height = height if height != 'latest' else self.latest_height()
        return call_chain('block', str(height))

    def block_results(self, height='latest'):
        height = height if height != 'latest' else self.latest_height()
        return call_chain('block_results', str(height))

    def chain(self, min_height, max_height='latest'):
        max_height = max_height if max_height != 'latest' else self.latest_height()
        return call_chain('blockchain', str(min_height), str(max_height))

    def commit(self, height='latest'):
        height = height if height != 'latest' else self.latest_height()
        return call_chain('commit', str(height))

    def query(self, path, data=None, height=None, proof=False):
        return call_chain('abci_query', path, fix_address(data), str(height) if height is not None else None, proof)

    def broadcast_tx_commit(self, tx):
        return call_chain('broadcast_tx_commit', tx)

    def broadcast_tx_sync(self, tx):
        return call_chain('broadcast_tx_sync', tx)

    def broadcast_tx_async(self, tx):
        return call_chain('broadcast_tx_async', tx)

    def tx(self, txid):
        return call_chain('tx', txid)


class RPC:
    def __init__(self):
        self.wallet = Wallet()
        self.staking = Staking()
        self.address = Address()
        self.multisig = MultiSig()
        self.chain = Blockchain()

    def raw_tx(self, inputs, outputs, view_keys):
        return call('transaction_createRaw', inputs, outputs, view_keys)


if __name__ == '__main__':
    fire.Fire(RPC())
