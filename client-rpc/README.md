# Crypto.com Chain Client JSON-RPC server (client-rpc)

This is the client JSON-RPC server

## How to run the JSON-RPC server

```
$ client-rpc --chain_id <CHAIN_ID>
```
The string passed to `chain_id` is the last two hex digits of the chain id.

## Arguments

- `chain_id`: (Required) The last two hex digits of the chain id
- `host`: The host name of the server
- `port`: The port the server should listen to

## Wallet Reauest argument

Most of the JSON-RPC accepts a WalletRequest, which has the following structures:
- name
  - Name of the wallet
- passphrase
  - Passphrase used to encrypt the wallet
```
{
    "name": "<Wallet Name>",
    "passphrase": "<Wallet Passphrase>"
}
```

## JSON-RPC avaiable:

- wallet_create
  - Create a wallet with a new address
  - Arguments
    1. Wallet Request
  - Result
    - Wallet ID: String
- wallet_addresses
  - List all addresses of a wallet
  - Arguments
    1. Wallet Request
  - Result
    - Address list: String[]
- wallet_balance
  - Return balance of a wallet
  - Arguments
    1. Wallet Request
  - Result
    - Balance: String
- wallet_sendtoaddress
  - Send funds from wallet to an address
  - Arguments
    1. Wallet Request
    2. To address: String
    3. Balance: String
- wallet_transactions
  - List all transactions of a walle
  - Arguments
    1. Wallet Requestt
  - Result
    - Transaction Change List: TransactionChange[]
- sync
  - Synchronize the index
- sync_all
  - Clean synchronize of the index
