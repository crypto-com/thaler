///! This module contains additional parts that are a part of the MLS draft spec,
///! but are required for resolving relevant open issues in the draft spec.
///!
///! At the moment, one issue is that the node generating Commit/Welcome
///! may put "bogus" in the ciphertext, which will block nodes (newly joining or on the affected
///! path) from obtaining the new group state.
///! The sketched out / unverified solution to that is that the affected member may
///! reveal the shared secret, so that other members can verify that the affected member
///! received a bad update.
///!
///! NOTE: https://mailarchive.ietf.org/arch/msg/mls/DCEKbsnoRKmFTmCuMT-rHIfDapA/
///! one discussed issue is that the attacker may choose the ephemeral pubkey,
///! such that some previous secret value is revealed to him through this "NACK" mechanism.
///! The suggestion is to use Schnorr NIZK proof of the ephemeral pubkey for every ciphertext,
///! but:
///! 1) this is clumsy, as the HPKE setup API doesn't expose the ephemeral secrets.
///! 2) in our case / threat model, it does not seem to matter:
///! - if the attacker can do something like this, it means the attacker managed to breach TEE
///! (unless it's through a bug in the Rust code itself)
///! - if the attacker breached TEE, the "expected" worst case is
///!   "breaking confidentiality" temporarily, i.e. they can read old ledger records
///! -> they don't need to produce tweaked MLS handshakes messages for that,
///!    they could instead "unseal" old TEE-sealed data.
///!
///! the "unexpected" worst case would be breaking ledger integrity (such as through DoS
///! on certain honest nodes / MLS members) which should be prevented
///! by handshake NACK mechanism + BFT consensus.
mod dleq;

pub use dleq::NackDleqProof;
