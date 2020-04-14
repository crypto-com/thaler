# Changelog

*Unreleased*

## v0.4.0

### Breaking changes
* *chain-abci* [1239](https://github.com/crypto-com/chain/pull/1239): basic versioning
* *chain-abci* [1090](https://github.com/crypto-com/chain/pull/1090): upper bounds of reward parameters changed
* *chain-abci* [1100](https://github.com/crypto-com/chain/pull/1100): account nonce increased after reward distribution
* *chain-abci* [1292](https://github.com/crypto-com/chain/pull/1292): implements new punishment and staking state transition specification and new nonce logic
* *chain-storage* [1424](https://github.com/crypto-com/chain/pull/1424): add two columnes to the database
* *chain-core* [1162](https://github.com/crypto-com/chain/pull/1162): transaction witness contains BIP-340-compatible Schnorr signatures (instead of the previous WIP scheme)
* *chain-core* [1325](https://github.com/crypto-com/chain/pull/1325): blake3 for message digest (txid) + tree hashing
* *chain-core* [1222](https://github.com/crypto-com/chain/pull/1258): Add common outer type for public(non-enclave) tx, tx serialization is changed.
* *client* [1158](https://github.com/crypto-com/chain/pull/1158): "deposit-amount" is the default flow for client-cli when doing deposit
* *client* [1185](https://github.com/crypto-com/chain/pull/1185): public and private key pairs stored in wallet, use public_key + wallet_name as key to store the multi_sig_address
* *client* [1325](https://github.com/crypto-com/chain/pull/1325): encryption keys derived using blake3

### Features
* *client* [1072](https://github.com/crypto-com/chain/pull/1072): airgap-friendly workflow for client
* *client* [1136](https://github.com/crypto-com/chain/pull/1136): logo and version number with git commit in client
* *client* [1106](https://github.com/crypto-com/chain/pull/1106): import/export of non-HD keys

### Improvements
* *client* [1099](https://github.com/crypto-com/chain/pull/1099): client-cli asks to confirm the value
* *client* [1074](https://github.com/crypto-com/chain/pull/1074): watch-only mode can be used in client-cli
* *client* [1131](https://github.com/crypto-com/chain/pull/1131): checking of generated transactions in client

### Bug Fixes
* *chain-abci* [1092](https://github.com/crypto-com/chain/pull/1092): rewards may be recorded for inactive validators
* *chain-abci* [1116](https://github.com/crypto-com/chain/pull/1116): uncommitted changes may be persisted

## v0.3.1

*February 24, 2020*

This release contains a hotfix for two client issues in the 0.3.0 release (the binaries for chain-abci, enclaves, and dev-utils remain the same).

### Bug Fixes
* *client* [1117](https://github.com/crypto-com/chain/pull/1117): lightweight verification may fail with blocks with multiple transactions due to a different order of txids in btreemap
* *client* [1118](https://github.com/crypto-com/chain/pull/1118): incorrect fee estimation

*February 16, 2020*

This release fixes some of the main issues discovered during the testnet 0.2 operation and implements
various improvements, notably deployment is simplified through major parts of ADR-001 being implemented.

## v0.3.0
### Breaking changes
* *client* [723](https://github.com/crypto-com/chain/pull/723) [830](https://github.com/crypto-com/chain/pull/830): uses argon2 function for its internal storage key derivation.
* *client* [976](https://github.com/crypto-com/chain/pull/976) Missing MultiSig pubkey methods in ClientRPC and ClientCLI
 -- Rename client-rpc method `wallet_newMultiSigAddressPublicKey` to  `multiSig_newAddressPublicKey`
* *client* [1035](https://github.com/crypto-com/chain/pull/1035): querying public information doesn't require a wallet name / passphrase
* *chain-abci* [982](https://github.com/crypto-com/chain/pull/982): a different reward formula + paramater renaming in genesis.json
* ADR-001 [1073](https://github.com/crypto-com/chain/pull/1073): tx-validation-app subsumed by chain-abci and sealed transaction payloads are stored in chain-abci's storage

### Features
* *client* [695](https://github.com/crypto-com/chain/pull/695): export and import transaction -- transactions that do not include receiver's view key can be exported, giving a base64 encoded plain transaction string which can be imported by the receiver.
* *client* [916](https://github.com/crypto-com/chain/pull/916): wallet delete API
* *client* [921](https://github.com/crypto-com/chain/pull/921): high-level deposit transaction workflow (note [it has a bug pending to be fixed](https://github.com/crypto-com/chain/issues/949))
* *client* [1058](https://github.com/crypto-com/chain/pull/1058): transaction details display

### Improvements
* *client* [736](https://github.com/crypto-com/chain/pull/736): more details in abci query errors
* *client* [701](https://github.com/crypto-com/chain/pull/701): tracking of utxo status after a transaction broadcast
* *client* [842](https://github.com/crypto-com/chain/pull/842): waiting for tendermint node to catch up before syncing
* *client* [841](https://github.com/crypto-com/chain/pull/841): not entering duplicate view keys in transaction metadata
* *client* [848](https://github.com/crypto-com/chain/pull/848): transaction type shown in history
* *client* [928](https://github.com/crypto-com/chain/pull/928): addresses sorted in creation order
* *client* [959](https://github.com/crypto-com/chain/pull/959): extra details in client-cli help messages
* *client* [1051](https://github.com/crypto-com/chain/pull/1051): warning for potentially outdated information in client-cli
* *chain-abci* [843](https://github.com/crypto-com/chain/pull/843): sanity check for historical state querying
* *chain-abci* [875](https://github.com/crypto-com/chain/pull/875): arguments can be read from a yaml file
* *chain-abci* [1055](https://github.com/crypto-com/chain/pull/1055): different log levels for missing liveness tracking information
* *chain-tx-enclave* [740](https://github.com/crypto-com/chain/pull/740): more logging
* *chain-tx-enclave* [836](https://github.com/crypto-com/chain/pull/836): retries for IAS in tx-query
* *chain-tx-enclave* [931](https://github.com/crypto-com/chain/pull/931): checking required environment variables are set in tx-query
* *chain-tx-validation* [845](https://github.com/crypto-com/chain/pull/845): more descriptive error message for non-existant accounts

### Bug Fixes
* *client* [969](https://github.com/crypto-com/chain/pull/969): client-cli incorrect fee display in history
* *client* [995](https://github.com/crypto-com/chain/pull/995): pending balance amount fixed for deposits
* *chain-abci* [1008](https://github.com/crypto-com/chain/pull/1008):  unbonded or unjailed validator cannot rejoin the validator set 
* *chain-abci* [933](https://github.com/crypto-com/chain/pull/933): unbonding any amount removes a validator

*January 3, 2020*

This hotfix release patches the client with the fixes for bugs discovered in the 0.2.0 release
(the binaries for chain-abci, enclaves, and dev-utils remain the same).

## v0.2.1

### Bug Fixes
* *client* [734](https://github.com/crypto-com/chain/pull/734): client-cli sync hangs after sync complete
* *client* [735](https://github.com/crypto-com/chain/pull/735): websocket rpc method id may overlap 
* *client* [737](https://github.com/crypto-com/chain/pull/737): block id field in vote could be empty

### Improvements
* *client* [736](https://github.com/crypto-com/chain/pull/736): unclear client error message when tx-query not set


*December 20, 2019*

This release fixes some of the bugs discovered in deployment of v0.1 and is based on the released 1.1.0 version
of Rust SGX SDK (0.1.0 used a beta version of 1.1.0).  

## v0.2.0

### Breaking changes
* *client* [703](https://github.com/crypto-com/chain/pull/703): HD wallet generate view key with a different account index.

### Improvements
* *dev-utils* [692](https://github.com/crypto-com/chain/pull/692): dev-utils init command logs error when it goes wrong
* *client* [698](https://github.com/crypto-com/chain/pull/698): watch-only mode
* *client* [700](https://github.com/crypto-com/chain/pull/700): client prints all environment variables in help
* *client* [705](https://github.com/crypto-com/chain/pull/705): client rejects weak passphrases based on zxcvbn score 

### Bug Fixes
* *chain-abci* [704](https://github.com/crypto-com/chain/pull/704): app hash was changing in v0.1 even though app state didn't change
* *client* [694](https://github.com/crypto-com/chain/pull/694): trusted state serialization is symmetric
* *dev-utils* [703](https://github.com/crypto-com/chain/pull/703): generating correct app hashes 

*December 17, 2019*

The release is a more complete alpha version meant to be deployed on the second iteration of the public testnet.
There are no guarantees on future API and binary compatibility at this stage.


## v0.1.0

### Features
* *chain-abci*: early punishment logic -- validators that do not maintain liveness or exhibit Byzantine faults are punished 
by having their respective account states jailed and their associated stake slashed. Slashing amount
depends on the configurable network parameter as well as how many validators are being punished at the same time. Unjailing can happen manually using a special transaction type (UnjailTx).
* *chain-abci*: early reward distribution logic -- fees and emissions (using an exponential decay) from the initial rewards pool are periodically distributed to validators.
* *chain-abci*: dynamic validator set -- new validator nodes can join the validator set by sending a special transaction type (NodeJoinTx).
* *chain-abci*: more complete and flexible genesis configuration -- the genesis file now contains the network parameters guarding the punishment and rewards logic, and the initial distribution is more flexible (e.g. amounts can be unbonded from a custom time instead of a genesis time).
* *chain-tx-enclave*: transaction workflows -- basic flows around transaction data confidentiality are sketched out in the client and validation and query enclaves (broadcasted transactions are encrypted with a static mock key; client can connect to an enclave over a remotely attested TLS connection and query transactions that were previously sealed on that node).
* *client*: HD-wallet -- using the standardized BIP44 derivations and BIP39 mnemonics.
* *client*: early lite verification -- [block-level lite client verification](https://github.com/tendermint/tendermint/blob/master/docs/architecture/adr-044-lite-client-with-weak-subjectivity.md) using an early tendermint-rs implementation and basic app hash checking

### Bug Fixes
* [365](https://github.com/crypto-com/chain/pull/365) Creating a transfer address also creates a staking address
* a lot of others, but as we didn't maintain this changelog, it'd take ages to list them all :/

### Improvements
* quite a few improvements in client, e.g. not signing every intermediate transaction used in fee estimation 

### Breaking changes
* *client*: internals changed a lot: many dependency bumps + a different storage schema
* *chain-abci*: app state format changes in genesis.json + storage format 
* *chain-tx-enclave*: changes in enclave-protocol and in EDL

### Known Limitation
* (compile-time) static mock key for transaction obfuscation
* many other things (e.g. full node synchronization needs to happen from genesis, no UTXO commitments)

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
