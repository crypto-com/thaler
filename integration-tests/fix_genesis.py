import sys
import base64
import hashlib
import json

GENESIS = json.load(open(sys.argv[1]))


def get_voting_power(state):
    cointype, coin = state
    assert cointype == 'Bonded'
    return str(int(int(coin) / (10 ** 8)))


def validator_addr(pubkey_base64):
    return hashlib.sha256(base64.b64decode(pubkey_base64)).hexdigest().upper()[:40]


GENESIS['validators'] = [
    {
        'address': validator_addr(node[2]['value']),
        'pub_key': node[2],
        'power': get_voting_power(GENESIS['app_state']['distribution'][addr]),
    }
    for addr, node in GENESIS['app_state']['council_nodes'].items()
]

json.dump(GENESIS, open(sys.argv[1], 'w'), indent=4)
