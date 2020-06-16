# Roadmap

The roadmap for the current codebase can be tracked via milestones and release plans
on Github and Zenhub.

In this document, we summarize the "long-term" roadmap, i.e. some plans beyond
the immediate development work, while still adhering to the [initial design philosophy](PHILOSOPHY.md)
(e.g. simplicity over flexibility).

## Cross-chain interoperability
Starting with https://github.com/crypto-com/settlement-cro
it would good continuing the work of expanding cross-ledger payment / value-transfer capabilities.
One other area of interest is adding IBC support to Chain: https://github.com/informalsystems/ibc-rs
The use case of IBC is for moving "assets": https://forum.interledger.org/t/whats-the-difference-between-cosmos-and-interledger-ibc-inter-blockchain-communication-vs-ilp/354/3

As CRO on Crypto.com Chain is used/specialized for payments and network operations (staking),
one may want to move it to a network with a different application / purpose (e.g. DEX). With IBC,
one could potentially move native-CRO from Crypto.com Chain to other networks and back.

## Other TEE in confidentiality
The initial prototype started with Intel SGX as TEE solution option because of its commercial availability.
In the long-term, we will explore other TEE options that can execute as additional targets
(so that the network is more heterogenous).
This section overviews the other TEE technology at the time writing.

### AMD-SEV
The isolation here is on the VM level. So it would require running some "trusted" OS,
i.e. some minimal unikernel / libraryOS or seL4 that would execute the enclave code (+ possibly storage).
Enarx has a small demo: https://github.com/enarx/demo/tree/master/amd-sev
This needs to be considered with the new hardware generation,
as the current one's remote attestation 
has been breached and cannot be fixed / revoked (unlike SGX 
which had CPU microcode fixes and TCB recovery process): https://arxiv.org/abs/1908.11680 

### IBM PEF
https://developer.ibm.com/articles/l-support-protected-computing/
Similar to AMD-SEV, the isolation appears to be on the VM level.
It does not seem to be yet available on the market.
There is also OpenPOWER Sanctum that should be isolating on the process level (similar to SGX),
but there is not much information about it and does not seem to be available either.

### AWS Nitro
The same requirements as with AMD-SEV, as the isolation is on the VM/instance level.
There are currently not many details about how the code attestation works,
for example whether the attestation payload can be independently verified by a remote party
(e.g. if it contains some binding to a AWS root certificate or a similar measure that is publicly known)
or if it's only host-based attestation that only makes sense to that particular AWS account owner.

### RISC-V Keystone 
There is a lot of research and development happening: https://keystone-enclave.org
and it may be possible to isolate more on the process level.
But currently, there is no commercially available system.
With https://github.com/keystone-enclave/keystone/blob/master/docs/source/Keystone-Applications/Attestation.rst#device-root-keys
it would only be a plain host-based attestation which one cannot remotely verify.
Full remote attestation would require the manufacturer (or some other trusted party) to sign and publish the public keys
derived from the (fused) device root keys.

### Arm TrustZone
TrustZone does not provide the isolation one gets with the other technologies
-- e.g. there is not much isolation among trusted applications
(there is only isolation of trusted applications from the operating system).
There is research work that aims to do that: https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_01A-1_Brasser_paper.pdf
but it does not protect against physical attacks.
One will additional SoC features (cryptographic co-processors, secure boot,
assistance for encrypted memory etc.) in order to securely leverage TrustZone.
In general, one will need a trusted / custom hypervisor (e.g. seL4) + application to run on the device and attestation 
on devices hardcoded with this hypervisor + application-only.

## Wallet Backend / TQE -- Private Indexing
Currently, the (light client) wallet needs to keep track of potential transaction payloads it may be involved in
and request their payloads via TQE.
It would be more ideal if the wallet could ask the enclave application on a full node to index transactions for the wallet
*WITHOUT* the full node learning wallet details (what transactions are mapped to what public view key):
this should be possible with ORAM-based techniques -- see https://eprint.iacr.org/2018/1024.pdf
The question is whether the ORAM overhead would be feasible with a large number of transactions.

## Offchain TEE applications
TEE can be leveraged beyond the base layer transaction data confidentiality.
The general idea here is to use TEE application as a "third party" in the multi-sig construction,
which can enforce additional constraints on unlocking the transaction output.

### Smart Contracts
As the smart contract logic executes inside TEE, it can be written in any programming language
as long as that language's runtime can be ported to TEE (or be e.g. compiled to WASM
which has a runtime written in Rust). In general, core "smart contract" TEE bundle will need:

1. some basic wallet functionality (keypair generation; UTXO selection; keeping track of balance)
2. light client implementation
3. attested secure communication channel (e.g. TLS with attestation payload)

Using this bundle, one can create "smart contracts" without changing the blockchain structure / consensus logic.
Example: peer-to-peer betting. Alice wants to bet Team A wins, Bob wants to bet Team B wins -- 
they send coins to an address constructed as 2-of-3 where the "contract"'s pubkey is generated inside TEE
and the "contract" secret key can be in both Alice's and Bob's machine's TEE. The "contract"'s logic will be:

1) collect TX outputs locked into 2-of-3 via the light client
2) get (trusted) time from the light client
3) fetch the match result from HTTPS and parse
4) if team A wins, generate TX to send all to Alice and execute MuSig with Alice
5) if team B wins, generate TX to send all to Bob and execute MuSig with Bob
6) if draw, generate TX to send back to Alice and Bob their shares (execute MuSig with either Alice or Bob)
7) if error, do nothing until timeout -- after that, procedure similar to draw (6)

### Stake pooling
Similarly to smart contracts, the secret to the staking address can be generated inside TEE.
The pool operator would deploy a node and get its nodejoin signed by the pool TEE staking address.
The staking TEE application can expose both its staking address and "transfer address",
and expose endpoint where one would send a TX payload + witness...
Based on the TX payload (given it checks via the light client, TX was confirmed) + witness,
it can track how much was transferred from whom.

The TEE application keeps track of how much each contributor added, and calculate
how much rewards they deserve. The TEE staking application can then
periodically "re-balance" stake and transfer balances,
so that all stake contributors can get a certain percentage of their share
immediately paid upon a request.

### Faster payment network with privacy
Additional networks for faster payments (if the PBFT-like consensus becomes a bottleneck)
can spin off the main network, as they may have lower guarantees
(e.g. broadcast instead of consensus with fixed parties: https://arxiv.org/pdf/2003.11506.pdf).
TEE can be leveraged for strengthening the network guarantees as well as preserving the privacy.

## Client support for "scriptless" scripts
As these end up to be plain Schnorr signatures, they can work with the existing transaction validation
code, while they can enforce further lightweight smart contract-like constraints:
https://github.com/ElementsProject/scriptless-scripts/tree/master/md

## Extended transaction output and witness
While the existing transaction outputs can support variety of use cases,
it may be desirable to provide another transaction output type
which can enforce additional network-enforced constraints (while still being simple
conceptually and implementation-wise).

### More fine-grained time-locking
Currently, time-locks are on the whole output.
For some applications (e.g. certain payment channel constructions),
one may need a more fine-grained locking, i.e. on the "leaf" signer level,
so one can lock output against a condition such as: either A&B sign OR A (after time X) signs alone.

Instead of only presenting Merkle proofs with pubkeys in witnesses,
one would present Merkle proofs of pubkeys+`Option<Timespec>` in witnesses
and if the time-lock is specified, it'd be checked against the previous block time.

### Covenants
Covenants can encumber the transaction output, such that 
the transaction that tries to consume it as an input needs to do
in a certain way (e.g. one can only pay to certain whitelisted addresses): https://bitcoinops.org/en/topics/covenants/

One common promising use case is "vaults" where one can reduce
the risk when private keys are stolen by an attacker, as the attacker
has limited options of what kind of transactions he can construct.
Broadcasting these transactions may then alert the owner who can
use a dedicated "backup" private key to sign transactions that
would take back stolen funds.
