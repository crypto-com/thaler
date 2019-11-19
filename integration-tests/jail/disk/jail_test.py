#!/usr/bin/python3
import docker
import json
import requests
import datetime
import time

def get_containers() :
    client = docker.from_env()
    containers= client.containers.list()
    ret= {}
    for container in containers:
        id = container
        #ret[id.name]= id.id
        ret[id.name]= container
    return ret
    

#show_containers()
# tendermint rpc

server="http://localhost:26657"
client_rpc= "http://localhost:9981"
headers = {
    'Content-Type': 'application/json',
}


def get_staking_state(name, passphrase, addr):
    q = {
        "method": "staking_state",
        "jsonrpc": "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }, addr],
        "id": "staking_state"
    }
    data = json.dumps(q)
    response = requests.post(client_rpc, headers=headers, data=data)
    return response.json()["result"]




def create_staking_address(name, passphrase):
    q = {
        "method": "wallet_createStakingAddress",
        "jsonrpc": "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }],
        "id": "wallet_createStakingAddress"
    }
    data = json.dumps(q)
    response = requests.post(client_rpc, headers=headers, data=data)


def restore_wallet(name, passphrase, mnemonics):
    q = {
        "method": "wallet_restore",
        "jsonrpc": "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }, mnemonics],
        "id": "wallet_restore_hd"
    }
    data = json.dumps(q)
    response = requests.post(client_rpc, headers=headers, data=data)
    print("restore wallet {}".format(name), response.json())

def restore_wallets():
    restore_wallet(
        "a", "1",
        "speed tortoise kiwi forward extend baby acoustic foil coach castle ship purchase unlock base hip erode tag keen present vibrant oyster cotton write fetch"
    )


def create_addresses():
    create_staking_address("a", "1")
    create_staking_address("a", "1")



def unjail(name, passphrase, address):
    q = {
        "method": "staking_unjail",
        "jsonrpc": "2.0",
        "params": [{
            "name": name,
            "passphrase": passphrase
        }, address],
        "id": "staking_unjail"
    }
    data = json.dumps(q)
    response = requests.post(client_rpc, headers=headers, data=data)
    print(response.json())
    return response.json()


def check_validators() :
	try: 
		x= requests.get('{}/validators'.format(server))
		data =len(x.json()["result"]["validators"])
		return data
	except requests.ConnectionError:
 		return 0
	except:
		assert False

def wait_for_ready(count) :
	while True:
		validators=check_validators()
		print("{}  current validators={}  waiting for validators={}".format(datetime.datetime.now(),validators, count))
		if count== validators :
			print("validators ready")
			break
		time.sleep(60)


def test_jailing() :
    print("test jailing")
    wait_for_ready(2)
    containers=get_containers()
    print(containers)
    if "jail_chain1_1" in containers :
        assert True
    else :
        assert False
    print("wait for jailing")
    time.sleep(10)
    jailthis = containers["jail_chain1_1"]
    print("jail = " , jailthis)
    jailthis.kill()
    wait_for_ready(1)
    #jailed
    containers=get_containers()
    print(containers)
    if "jail_chain1_1" in containers :
        assert False
    else :
        assert True 
    print("jail test success")


def test_unjailing() :
    print("test unjailing")
    wait_for_ready(1)

    count=2
    while True:
        unjail("a","1", "0xe5b4b42406a061752c78bf5c4d6d6fccca0b575f")
        state= get_staking_state("a","1", "0xe5b4b42406a061752c78bf5c4d6d6fccca0b575f")
        punishment=state["punishment"] 
        print("punishment {}".format(punishment))
        if punishment== None :
            print("unjailed!!")
            break
        else :
            print("still jailed")
        time.sleep(10)
    print("unjail test success")

############################################################################3
test_jailing()
restore_wallets()
create_addresses()
test_unjailing()
