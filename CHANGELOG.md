# Changelog

*September 12, 2019*

A quick bug fix on top of 0.0.2

## v0.0.3

### Bug fixes
* [373](https://github.com/crypto-com/chain/pull/373) client-index auto-sync didn't work correctly

*September 11, 2019*

A small patches (mainly dependency bumps) to the released version

## v0.0.2

### Features
* [360](https://github.com/crypto-com/chain/pull/360) command to remove a wallet from client-rpc auto-sync

### Bug fixes
* [368](https://github.com/crypto-com/chain/pull/368) client-cli can select the network via an environment variable for address display

### Improvements
* [364](https://github.com/crypto-com/chain/pull/364) fewer logs in client-rpc


*September 6, 2019*

The release is an incomplete alpha version meant to be deployed on the first iteration of the public testnet.
There are no guarantees on future API and binary compatibility at this stage.

## v0.1.0 (Unreleased)

### Features

### Bug Fixes
* [365](https://github.com/crypto-com/chain/pull/365) Creating a transfer address also creates a staking address

## v0.0.1

### Features
* initial genesis procedure based on one-off snapshotting the ERC20 contract state and several allocation mentioned in the original whitepaper
* initial rewards pool
* initial configurable linear fee scheme
* initial basic network operations related to bonded stake management
* sketched out obfuscated transaction format
* transaction binary payloads use [SCALE](https://github.com/paritytech/parity-scale-codec#parity-scale-codec) codec
* transaction validation in enclaves isolated in a separate process reached via a 0MQ socket
* threshold multi-signature support using Merkle trees of combined public keys and the Schnorr MuSig scheme
* * (for the sample use case in the context of what was marketed as "Proof of Goods & Services Delivered", see https://github.com/crypto-com/multisig-demo ) 
* client library "backend" support for transfers, multi-signatures and staking operations

### Known Limitation
Far too many to list them all (e.g. a validator set fixed at genesis or temporarily mocked transaction privacy) :)

*Pre-alpha versions*

While versioning was not strictly followed in the pre-alpha stages, there were a few tagged releases that signalled format changes that broke the client functionality:

* `pre-alpha-feeless-client`: the change after this tag added the linear fee scheme; the client could have potentially construct invalid transactions due to not accounting for the fee
* `pre-alpha-no-account-genesis`: before staking operations support, the initial "state" was constructed from transactions with no inputs; the change after this tag added the extra staking-related operations
* `pre-alpha-pre-enc-tx`: the change after this tag sketched out the obfuscated transaction format
