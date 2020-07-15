#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import re
import json

PASSPHRASE = "123456"
def run(cmd, args=None):
    p = subprocess.Popen(cmd,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         universal_newlines=True,
                         bufsize=0)
    if isinstance(args, list) and args:
        p.stdin.writelines("\n".join(args) + "\n")
    elif args:
        p.stdin.writelines("{}\n".format(args))
    output, err = p.communicate()
    if err and "using mock" not in err.lower():
        raise Exception("stdout: {}, stderr: {}".format(output, err))
    return remove_color(output)


def to_coin(balance):
    # 8 decimal
    MAX_COIN_DECIMALS = 100000000
    return int(float(balance) * MAX_COIN_DECIMALS)


def parse_auth_token(text):
    pattern = r"Authentication token:\s*(?P<auth_token>([0-9a-fA-F])+)"
    match = re.search(pattern, text)
    if match:
        return match.groupdict()["auth_token"]
    else:
        raise Exception(text)


def remove_color(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


# create
class Wallet():
    def __init__(self, name, passphrase=PASSPHRASE):
        self.name = name
        self.passphrase = passphrase
        self._auth_token = None

    def new(self, wallet_type):
        cmd = ["client-cli", "wallet", "new", "-n", self.name, "-t", wallet_type]
        args = [self.passphrase, self.passphrase]
        text = run(cmd, args)
        self._auth_token = parse_auth_token(text)

    def delete(self):
        cmd = ["client-cli", "wallet", "delete", "-n", self.name]
        args = self.passphrase
        text = run(cmd, args)
        last_line = text.splitlines()[-1]
        if "Error" in last_line:
            raise Exception(last_line)

    @property
    def auth_token(self):
        if self._auth_token:
            return self._auth_token
        cmd = ["client-cli", "wallet", "auth-token", "-n", self.name]
        args = self.passphrase
        text = run(cmd, args)
        auth_token = parse_auth_token(text)
        self._auth_token = auth_token
        return auth_token

    def view_key(self, private = False):
        cmd = ["client-cli", "view-key", "-n", self.name]
        if private:
            cmd.append("--private")
        args = self.auth_token
        text = run(cmd, args)
        pattern = r"View Key:\s*(?P<view_key>([0-9a-fA-F])+)"
        match = re.search(pattern, text)
        if match:
            self._view_key = match["view_key"]
            return self._view_key
        else:
            raise Exception(text)

    @classmethod
    def list(cls):
        cmd = ["client-cli", "wallet", "list"]
        text = run(cmd)
        return re.findall(r"Wallet name: (\S+)", text)

    """
    restore wallet
    """
    @classmethod
    def restore(cls, name, passphrase, mnemonic):
        wallet = Wallet(name, passphrase)
        cmd = ["client-cli", "wallet", "restore", "-n", name]
        args = [passphrase, passphrase, mnemonic, mnemonic]
        text = run(cmd, args)
        last_line = text.splitlines()[-1]
        if "Authentication token" not in last_line:
            raise Exception(last_line)
        wallet._auth_token = parse_auth_token(text)
        return wallet

    """
    restore basic and return wallet
    """
    @classmethod
    def restore_basic(cls, name, passphrase, private_view_key):
        cmd = ["client-cli", "wallet", "restore-basic", "-n", name]
        args = [passphrase, passphrase, private_view_key]
        text = run(cmd, args)
        auth_token =parse_auth_token(text)
        wallet = Wallet(name, passphrase)
        wallet._auth_token = auth_token
        return wallet


    """
    export wallet directly
    wallet_list: a list of Wallet
    """
    @classmethod
    def export_without_file(cls, wallet_list=[]):
        wallets_name = [w.name for w in wallet_list]
        wallets_auth_token = [w.auth_token for w in wallet_list]
        cmd = ["client-cli", "wallet", "export", "-n", ",".join(wallets_name)]
        text = run(cmd, wallets_auth_token)
        if "Error" in text:
            raise Exception(text)
        info = ""
        start = False
        for line in text.splitlines():
            if line.startswith('['):
                start = True
                info += line
                continue
            if start:
                info += line
        return json.loads(info)

    """
    export wallet to a file
    use `--from_file` and `--to_file` in the export
    """

    @classmethod
    def export_with_file(cls, from_file="/tmp/from_file", to_file="/tmp/to_file"):
        cmd = ["client-cli", "wallet", "export", "-f", from_file, "-t", to_file]
        text = run(cmd)
        if "Error" in text:
            raise Exception(text)
        return json.load(open(to_file))

    """
    import wallet from a file
    """

    @classmethod
    def import_from_file(cls, file="/tmp/to_file", passphrase=PASSPHRASE):
        wallet_info_list = json.load(open(file))
        for wallet in wallet_info_list:
            if not wallet["passphrase"]:
                wallet["passphrase"] = passphrase
        with open(file, "w") as f:
            json.dump(wallet_info_list, f)
        cmd = ["client-cli", "wallet", "import", "-f", file]
        run(cmd)

    """
    args:
        adress_type: transfer | staking
    """

    def list_address(self, address_type="transfer"):
        cmd = ["client-cli", "address", "list", "-n", self.name, "-t", address_type]
        args = self.auth_token
        text = run(cmd, args)
        if "Error" in text:
            raise Exception(text)
        addresses = []
        multisign_addresses = []
        for line in text.splitlines():
            if "Address: " in line:
                addr = line.split(":")[-1].strip()
                if len(addr.split()) > 1:
                    continue
                addresses.append(addr)
            if address_type == "transfer" and line.startswith("MultiSig Address: "):
                addr = line.split(":")[-1].strip()
                if len(addr.split()) > 1:
                    continue
                multisign_addresses.append(addr)
        result = {
            "address_type": address_type,
            "addresses": addresses,
        }
        if address_type == "transfer":
            result["multisign_addresses"] = multisign_addresses
        return result

    """
    create address
    args:
        address_type: transfer | staking
    return: the created address
    """

    def create_address(self, address_type="transfer", hardware_wallet_type=None):
        cmd = ["client-cli", "address", "new", "-t", address_type, "-n", self.name]
        if hardware_wallet_type:
            args = [self.auth_token, hardware_wallet_type]
        else:
            args = self.auth_token
        text = run(cmd, args)
        last_line = text.splitlines()[-1]
        if "New address:" in last_line:
            return last_line.split(":")[-1].strip()
        else:
            raise Exception(text)

    """
    return a list of public key
    """
    def list_pub_key(self, address_type="transfer"):
        cmd = ["client-cli", "address", "list-pub-key", "-n", self.name, "-t", address_type]
        args = self.auth_token
        text = run(cmd, args)
        if "Error" in text:
            raise Exception(text)
        return re.findall(r"\w{66}", text)

    @property
    def balance(self):
        cmd = ["client-cli", "balance", "-n", self.name]
        args = self.auth_token
        text = run(cmd, args)
        if "Error" in text:
            raise Exception(text)
        r = re.findall(r"(?<=\|)(\s*\d+\.*\d*\s*)(?=\|)", text)
        assert len(r) == 3
        result = {
            "total": to_coin(r[0]),
            "pending": to_coin(r[1]),
            "available": to_coin(r[2])
        }
        return result

    def state(self, staking_address):
        cmd = ["client-cli", "state", "--address", staking_address, "--name", self.name]
        text = run(cmd)
        if "Error" in text:
            raise Exception(text)
        result = {}
        for line in text.splitlines():
            if "|" in line:
                info = line.split("|")
                key = info[1].strip().lower().replace(" ", "_")
                value = info[2].strip()
                result[key] = value
        result["nonce"] = int(result["nonce"])
        result["bonded"] = to_coin(result["bonded"])
        result["unbonded"] = to_coin(result["unbonded"])
        # TODO: parse other values if we need
        return result

    def sync(
            self,
            force=False,
            disable_address_recovery=False,
            enable_fast_forward=True,
            batch_size=20,
            block_height_ensure=50,
    ):
        cmd = ["client-cli", "sync", "-n", self.name, "--batch-size", str(batch_size), "--block-height-ensure", str(block_height_ensure)]
        if force:
            cmd.append("--force")
        if disable_address_recovery:
            cmd.append("--disable-address-recovery")
        if enable_fast_forward:
            cmd.append("--enable-fast-forward")
        args = self.auth_token
        text = run(cmd, args)
        if "Error" in text:
            raise Exception(text)
        return text

class Transaction:
    def __init__(self, wallet, hardware=None):
        self.wallet = wallet
        self.hardware = hardware

    """"
    args:
        amount: in CRO amount
    """
    def unbond(self, staking_address, amount):
        amount = str(amount)
        if self.hardware:
            cmd = ["client-cli", "transaction", "--hardware", self.hardware, "new", "-t", "unbond", "-n", self.wallet.name]
        else:
            cmd = ["client-cli", "transaction", "new", "-t", "unbond", "-n", self.wallet.name]
        args = [self.wallet.auth_token, staking_address, amount, "Y"]
        state = self.wallet.state(staking_address)
        if to_coin(amount) > state["bonded"]:
            raise Exception("not enough coins to unbond, the bonded amount is {}".format(state["bonded"]))
        text = run(cmd, args)
        if "Error" in text:
            raise Exception(text)
        return text

    """
    args:
        amount: in CRO amount
    """
    def withdraw(self, staking_address, transfer_address, time_lock = None, view_keys=[]):
        if self.hardware:
            cmd = ["client-cli", "transaction",  "--hardware", self.hardware, "new", "-t", "withdraw", "-n", self.wallet.name]
        else:
            cmd = ["client-cli", "transaction", "new", "-t", "withdraw", "-n", self.wallet.name]
        args = [self.wallet.auth_token, staking_address, transfer_address, ",".join(view_keys), "Y"]
        text = run(cmd, args)
        if "Error" in text:
            raise Exception(text)
        return text

    def transfer(self, to_transfer_address, amount, lock_time = "", view_keys=[]):
        if self.hardware:
            cmd = ["client-cli", "transaction",  "--hardware", self.hardware, "new", "-t", "transfer", "-n", self.wallet.name]
        else:
            cmd = ["client-cli", "transaction", "new", "-t", "transfer", "-n", self.wallet.name]

        args = [self.wallet.auth_token, to_transfer_address, str(amount), "Y", str(lock_time) if lock_time else '', "N", ",".join(view_keys)]
        text = run(cmd, args)
        if "Error" in text:
            raise Exception(text)
        return text

    def deposit(self, to_staking_address, amount):
        if self.hardware:
            cmd = ["client-cli", "transaction",  "--hardware", self.hardware, "new", "-t", "deposit", "-n", self.wallet.name]
        else:
            cmd = ["client-cli", "transaction", "new", "-t", "deposit", "-n", self.wallet.name]
        args = [self.wallet.auth_token, to_staking_address, str(amount), "Y"]
        text = run(cmd, args)
        if "Error" in text:
            raise Exception(text)
        m = re.search("transaction id is: ([a-f0-9A-F]{64})", text)
        return m.groups()[0]

    # check the history of transaction
    @property
    def history(self):
        cmd = ["client-cli", "history", "-n", self.wallet.name]
        args = [self.wallet.auth_token]
        text = run(cmd, args)
        if "Error" in text:
            raise Exception(text)
        histories = []
        for index, line in enumerate(text.splitlines()):
            if index >= 4 and index % 2 == 0:
                data = line.replace(" ","").replace("|", " ").strip().split()
                history = {
                    "tx_id": data[0],
                    "side": data[1],
                    "amount": to_coin(data[2]),
                    "fee": to_coin(data[3]),
                    "tx_type": data[4],
                    "block_height": data[5],
                    "time": data[6],
                }
                histories.append(history)
        return histories

    def can_view_tx(self, tx_id):
        cmd = ["client-cli", "transaction", "show", "-n", self.wallet.name, "-i", tx_id]
        args = self.wallet.auth_token
        text = run(cmd, args)
        print(text)
        if "Transaction metadata" in text and \
            "Transaction inputs" in text and \
            "Transaction outputs" in text:
            return True
        else:
            return False