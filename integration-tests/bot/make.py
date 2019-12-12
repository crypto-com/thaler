#!/usr/bin/env python3
from chainbot import CLI
import json
import jsonpatch
a = CLI()
print("make config")
src=a._gen(count=2, chain_id='test-ab', expansion_cap=50000000000000000,  root_path='./', hostname='localhost')
patch = jsonpatch.JsonPatch([
    {'op': 'replace', 'path': '/nodes/0/bonded_coin', 'value':   3750000000000000000},
    {'op': 'replace', 'path': '/nodes/0/unbonded_coin', 'value': 1250000000000000000},
    {'op': 'replace', 'path': '/nodes/1/bonded_coin', 'value':   1250000000000000000},
    {'op': 'replace', 'path': '/nodes/1/unbonded_coin', 'value': 3700000000000000000},
    {'op': 'replace', 'path': '/nodes/0/base_port', 'value':26650},
    {'op': 'replace', 'path': '/nodes/1/base_port', 'value':26650},
    {'op': 'replace', 'path': '/nodes/0/hostname', 'value':'chain0'},
    {'op': 'replace', 'path': '/nodes/1/hostname', 'value':'chain1'},
    {'op': 'add', 'path': '/chain_config_patch/2', 'value': {"op":"replace", "path":"/slashing_config/slash_wait_period", "value":10} },
    {'op': 'add', 'path': '/chain_config_patch/3', 'value': {"op":"replace", "path":"/jailing_config/jail_duration", "value":86} },
    {'op': 'add', 'path': '/chain_config_patch/4', 'value': {"op":"replace", "path":"/jailing_config/block_signing_window", "value":20} },
    {'op': 'add', 'path': '/chain_config_patch/5', 'value': {"op":"replace", "path":"/jailing_config/missed_block_threshold", "value":10} },
])


dst=jsonpatch.apply_patch(src, patch)  
print(json.dumps(dst, indent=4))
a._prepare(dst)
apphash= json.load(open('./node0/tendermint/config/genesis.json'))['app_hash'] 
f = open("run_test_env.sh", "w")
f.write("export APP_HASH={}\n".format(apphash))
f.close()



print("apphash=", apphash)

