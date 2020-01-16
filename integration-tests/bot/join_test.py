#!/usr/bin/python3
import docker
import json
import requests
import datetime
import time
import jsonrpcclient
from chainrpc import RPC, Blockchain
from decouple import config
from chainbot import SigningKey
CURRENT_HASH = config('CURRENT_HASH', '')
class Program :
    def __init__(self) :
        self.rpc = RPC()
        self.blockchain = Blockchain()
        # wallet a
        self.node0_address = ""
        self.node0_address1 = ""
        self.node0_transfer_address = ""
        self.node0_mnemonics= ""

        # wallet b
        self.node1_address = ""
        self.node1_address1= ""
        self.node1_transfer_address = ""
        self.node1_mnemonics=""

        # wallet b
        self.node2_address = ""
        self.node2_mnemonics=""

        # keys
        self.keya=""
        self.keyb=""
        self.keyc=""

        self.headers = {
            'Content-Type': 'application/json',
        }

    def get_containers(self) :
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



    def get_staking_state(self,name, enckey, addr):
        return self.rpc.staking.state(addr, name, enckey)
       

    def create_staking_address(self,name, enckey):
        return self.rpc.address.create(name,'staking', enckey)

    def activate_sync(self):
        print("activate sync")
        self.rpc.wallet.sync_unlock("a", self.rpc.wallet.enckey("a"))
        self.rpc.wallet.sync_unlock("b", self.rpc.wallet.enckey("b"))
        self.rpc.wallet.sync_unlock("c", self.rpc.wallet.enckey("c"))
       
    def restore_wallets(self):
        print("restore wallets")
        self.rpc.wallet.restore(self.node0_mnemonics, "a")
        self.rpc.wallet.restore(self.node1_mnemonics, "b")
        self.rpc.wallet.restore(self.node2_mnemonics, "c")
            

    def create_addresses(self):
        self.create_staking_address("a", self.keya)
        self.create_staking_address("a", self.keya)
        self.create_staking_address("b", self.keyb)
        self.create_staking_address("b", self.keyb)
        self.create_staking_address("c", self.keyc)
        self.create_staking_address("c", self.keyc)
        

    def unjail(self,name, enckey, address):
        try:
            return self.rpc.staking.unjail(address, name, enckey)
        except jsonrpcclient.exceptions.JsonRpcClientError as ex:
            print("unjail fail={}".format(ex))

    def check_validators(self) :
        try: 
            x= self.rpc.chain.validators() 
            print(x)
            data =len(x["validators"])
            return data
        except requests.ConnectionError:
            return 0

    def check_validators_old(self) :
        x=self.blockchain.validators()["validators"]
        print("check validators")
        data =len(x)
        print("count={}  check_validators={}".format(data,x))
        return data
      

    def wait_for_ready(self,count) :
        initial_time=time.time() # in seconds
        MAX_TIME = 3600
        while True:
            current_time= time.time()
            elasped_time= current_time - initial_time
            remain_time = MAX_TIME - elasped_time
            validators=self.check_validators()
            if remain_time< 0 :
                assert False
            print("{0}  remain time={1:.2f}  current validators={2}  waiting for validators={3}".format(datetime.datetime.now(), remain_time, validators, count))
            if count== validators :
                print("validators ready")
                break
            time.sleep(10)


    def test_jailing(self) :
        print("test jailing")
        self.wait_for_ready(2)
        containers=self.get_containers()
        print(containers)
        assert "{}_chain1_1".format(CURRENT_HASH) in containers 
        print("wait for jailing")
        time.sleep(10)
        jailthis = containers["{}_chain1_1".format(CURRENT_HASH)]
        print("jail = " , jailthis)
        jailthis.kill()
        self.wait_for_ready(1)
        #jailed
        containers=self.get_containers()
        print(containers)
        assert "{}_chain1_1".format(CURRENT_HASH) not in containers
        print("jail test success")


    def test_unjailing(self) :
        initial_time=time.time() # in seconds
        print("test unjailing")
        self.wait_for_ready(1)

        MAX_TIME = 3600  
        while True:
            current_time= time.time()
            elasped_time= current_time - initial_time
            remain_time = MAX_TIME - elasped_time
            self.check_validators()
            if remain_time< 0 :
                assert False
            self.unjail("b", self.keyb, self.node1_address)
            state= self.get_staking_state("b", self.keyb, self.node1_address)
            print("state {}".format(state))
            punishment=state["punishment"] 
            print("{0}  remain time={1:.2f}  punishment {2}".format(datetime.datetime.now(), remain_time, punishment))
            if punishment is None :
                print("unjailed!!")
                break
            else :
                print("still jailed")
            time.sleep(10)
        print("unjail test success")

    ############################################################################3
    def main2 (self) :
        self.test_jailing()
        try :
            self.restore_wallets()
            self.activate_sync()
        except jsonrpcclient.exceptions.JsonRpcClientError as ex:
            print("wallet already exists={}".format(ex))
        self.create_addresses()
        self.test_unjailing()

    def prepare(self) :
        try :
            self.restore_wallets()
        except jsonrpcclient.exceptions.JsonRpcClientError as ex:
            print("wallet already exists={}".format(ex))
        self.keya=self.rpc.wallet.enckey("a")
        self.keyb=self.rpc.wallet.enckey("b") 
        self.keyc=self.rpc.wallet.enckey("c") 
        self.create_addresses()
        self.rpc.wallet.sync_unlock("a", self.keya)
        self.rpc.wallet.sync_unlock("b", self.keyb)
        
    def deposit(self):
        transactions= self.rpc.wallet.transactions("b", 0,1, False, self.keyb)
        assert len(transactions)==1
        tx= transactions[0]
        txid= tx["transaction_id"]
        tx_index=0
        print("txid={}".format(txid))
        print(transactions)
        deposit_address=self.node1_address
        print("deposit to {} from utxo tx {}-index {}".format(deposit_address, txid, tx_index))
        self.rpc.staking.deposit(deposit_address, [{'id':txid, 'index':tx_index}], "b", self.keyb)
        print("done")

        
    def withdraw(self):
        self.rpc.staking.withdraw_all_unbonded(self.node0_address1, self.node0_transfer_address,[], "a", self.keya)
        self.rpc.wallet.sync("a", self.keya)
        time.sleep(2)

    def transfer(self):
        balance_a= int(self.rpc.wallet.balance("a", self.keya)["total"])
        viewkey_a= self.rpc.wallet.view_key("a", False, self.keya)
        balance_b= int(self.rpc.wallet.balance("b", self.keyb)["total"])
        viewkey_b= self.rpc.wallet.view_key("b", False, self.keyb)
        print("a balance={}  viewkey={}".format(balance_a, viewkey_a))
        print(balance_a)
        print("b balance={}  viewkey={}".format(balance_b, viewkey_b))
        print("====================================")
        self.rpc.wallet.send(self.node1_transfer_address,balance_a, "a", [viewkey_a,viewkey_b], self.keya)
        time.sleep(5)
        self.rpc.wallet.sync("a", self.keya)
        self.rpc.wallet.sync("b", self.keyb)
        balance_a= int(self.rpc.wallet.balance("a", self.keya)["total"])
        viewkey_a= self.rpc.wallet.view_key("a", False, self.keya)
        balance_b= int(self.rpc.wallet.balance("b", self.keyb)["total"])
        viewkey_b= self.rpc.wallet.view_key("b", False, self.keyb)
        print("a balance={}  viewkey={}".format(balance_a, viewkey_a))
        print("b balance={}  viewkey={}".format(balance_b, viewkey_b))
        time.sleep(2)

    def wait_for_rpc(self):
        while True:
            try:
                wallets= self.rpc.wallet.list()
                break
            except requests.exceptions.ConnectionError as ex:
                print("connection fail {}".format(datetime.datetime.now()))
                time.sleep(5)
        print(json.dumps(wallets, indent=4))
    
    def join_node(self):
        print("join node")
        time.sleep(4);
        self.rpc.wallet.sync("b", self.keyb)
        node_name="node1"
        node_pubkey=self.node1_validator_pubkey
        node_staking_address= self.node1_address
        print("name={} pubkey={} staking={}".format(node_name, node_pubkey,node_staking_address))
        self.rpc.staking.join(node_name, node_pubkey, node_staking_address, "b", self.keyb)

    def wait_for_council_node(self):
        print("wait for council node")
        while True:
            res = self.rpc.staking.state( self.node1_address, "b",self.keyb)
            print("state={}".format(res))
            time.sleep(2)
            if res["council_node"] != None :
                break
        print("join success {} became a council node".format(self.node1_address))

    def wait_for_validators(self):
        print("wait for validators")
        while True:
            validators=self.check_validators()
            print("validators count={}".format(validators))
            time.sleep(2)
            if validators >= 2:
                break
        print("join success validator count {}".format(validators))



    def main (self) :
        self.wait_for_rpc()
        self.prepare()
        self.withdraw()
        self.transfer()
        self.deposit()
        self.join_node()
        self.wait_for_council_node()
        self.wait_for_validators()
        

    def read_info(self):
        print("read data")
        with open('info.json') as json_file:
            data = json.load(json_file)
        print(json.dumps(data,indent=4))
        self.node0_address= data["nodes"][0]["staking"][0]
        self.node0_address1= data["nodes"][0]["staking"][1]
        self.node0_transfer_address= data["nodes"][0]["transfer"][0]
        self.node0_validator_seed=data["nodes"][0]["validator_seed"]
        self.node0_validator_pubkey= SigningKey(self.node0_validator_seed).pub_key_base64()
    


        self.node1_address= data["nodes"][1]["staking"][0]
        self.node1_address1= data["nodes"][1]["staking"][1]
        self.node1_transfer_address= data["nodes"][1]["transfer"][0]
        self.node1_validator_seed=data["nodes"][1]["validator_seed"]
        self.node1_validator_pubkey= SigningKey(self.node1_validator_seed).pub_key_base64()
        

        self.node2_address= data["nodes"][2]["staking"][0]

        self.node0_mnemonics=data["nodes"][0]["mnemonic"]
        self.node1_mnemonics=data["nodes"][1]["mnemonic"]
        self.node2_mnemonics=data["nodes"][2]["mnemonic"]
        self.node2_validator_seed=data["nodes"][2]["validator_seed"]
        self.node2_validator_pubkey= SigningKey(self.node2_validator_seed).pub_key_base64()
        
    def display_info(self):
        print("jail test current hash={}".format(CURRENT_HASH))
        print("node0 staking= {}".format(self.node0_address))
        print("node0 staking1= {}".format(self.node0_address1))
        print("node0 transfer= {}".format(self.node0_transfer_address))
        print("node1 staking= {}".format(self.node1_address))
        print("node2 staking= {}".format(self.node2_address))
        print("node0 mnemonics= {}".format(self.node0_mnemonics))
        print("node1 mnemonics= {}".format(self.node1_mnemonics))
        print("node2 mnemonics= {}".format(self.node2_mnemonics))
        print("node0 validator seed= {}".format(self.node0_validator_seed))
        print("node0 validator pubkey= {}".format(self.node0_validator_pubkey))
        print("node1 validator seed= {}".format(self.node1_validator_seed))
        print("node1 validator pubkey= {}".format(self.node1_validator_pubkey))
        print("node2 validator seed= {}".format(self.node2_validator_seed))
        print("node2 validator pubkey= {}".format(self.node2_validator_pubkey))
        
        

p = Program()
p.read_info()
p.display_info()
p.main()
