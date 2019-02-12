use super::{request_passphrase, Error, ExecResult, SimpleKeyStorage, NONCE_SIZE};
use blake2::{Blake2s, Digest};
use chain_core::common::HASH_SIZE_256;
use chain_core::init::{address::REDEEM_ADDRESS_BYTES, coin::Coin};
use chain_core::tx::data::access::{TxAccess, TxAccessPolicy};
use chain_core::tx::witness::{
    redeem::EcdsaSignature,
    tree::{pk_to_raw, sig_to_raw},
    TxInWitness,
};
use chain_core::tx::{
    data::{address::ExtendedAddr, attribute::TxAttributes, input::TxoPointer, output::TxOut, Tx},
    TxAux,
};
use clap::ArgMatches;
use miscreant::aead::{Aes128PmacSiv, Algorithm};
use secp256k1::{
    aggsig::{add_signatures_single, export_secnonce_single, sign_single},
    key::{PublicKey, SecretKey},
    Message, Secp256k1,
};
use serde_cbor::ser::to_vec_packed;
use zeroize::Zeroize;

/// Transaction commands
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * storage - abstraction over encrypted secrets storage
///
pub fn tx_cmd(matches: &ArgMatches, storage: &SimpleKeyStorage) -> ExecResult {
    match matches.subcommand() {
        ("gen_tx", Some(sub_m)) => gen_tx(sub_m, storage),
        _ => Err(Error::ExecError(
            "Invalid keypair subcommand. Use `signer keypair -h` for help".to_string(),
        )),
    }
}

/// Validates arguments that should be tuples (pairs, triples, ...)
///
/// # Arguments:
///
/// * matches - arguments supplied from command line
/// * tuplesize - expected size of tuples
/// * arg - name of the argument
///
fn check_tupled_args(
    matches: &ArgMatches,
    tuplesize: usize,
    arg: &str,
) -> Result<Vec<String>, Error> {
    match matches.values_of_lossy(arg) {
        Some(x) => {
            if x.len() > 0 && x.len() % tuplesize == 0 {
                Ok(x)
            } else {
                Err(Error::ExecError(
                    format!("incorrect number of arguments to {}", arg).to_string(),
                ))
            }
        }
        _ => Err(Error::ExecError(
            format!("{} not provided", arg).to_string(),
        )),
    }
}

/// Returns a TX witnesses
///
/// # Arguments:
///
/// * name - keypair name to use
/// * sigt - requested signature types
/// * tx - Tx to sign (+ will be added view keys in attributes)
/// * extra_key - extra view key (generally the receiver's view key)
/// * storage - abstraction over encrypted secrets storage
///
fn get_sig_witnesses(
    name: String,
    sigt: Vec<SigType>,
    tx: &mut Tx,
    extra_key: Option<&str>,
    storage: &SimpleKeyStorage,
) -> Result<Vec<TxInWitness>, Error> {
    let key1n = format!("{}_spend", name);
    let key2n = format!("{}_view", name);
    let ck1 = storage.get_key(&key1n)?;
    let ck2 = storage.get_key(&key2n)?;
    let nonce1_start = ck1.len() - NONCE_SIZE;
    let nonce2_start = ck2.len() - NONCE_SIZE;
    let secp = Secp256k1::new();
    let extra_vk = if let Some(k) = extra_key {
        let dk = hex::decode(&k)?;
        let pk = PublicKey::from_slice(&secp, &dk)?;
        Some(pk_to_raw(&secp, pk))
    } else {
        None
    };
    let mut hasher = Blake2s::new();
    hasher.input(request_passphrase()?);
    let mut passphrase = hasher.result_reset();
    let mut algo = Aes128PmacSiv::new(&passphrase);
    let mut sk1 = SecretKey::from_slice(
        &secp,
        &algo.open(&ck1[nonce1_start..], key1n.as_bytes(), &ck1[..nonce1_start])?,
    )?;
    let mut sk2 = SecretKey::from_slice(
        &secp,
        &algo.open(&ck2[nonce2_start..], key2n.as_bytes(), &ck2[..nonce2_start])?,
    )?;
    passphrase.zeroize();
    let pk_view = pk_to_raw(&secp, PublicKey::from_secret_key(&secp, &sk2)?);
    tx.attributes
        .allowed_view
        .push(TxAccessPolicy::new(pk_view, TxAccess::AllData));
    if let Some(k) = extra_vk {
        tx.attributes
            .allowed_view
            .push(TxAccessPolicy::new(k, TxAccess::AllData));
    }
    let message = Message::from_slice(&tx.id())?;
    let ecsig = {
        let sig = secp.sign_recoverable(&message, &sk1)?;
        let (v, ss) = sig.serialize_compact(&secp);
        let r = &ss[0..32];
        let s = &ss[32..64];
        let mut sign = EcdsaSignature::default();
        sign.v = v.to_i32() as u8;
        sign.r.copy_from_slice(r);
        sign.s.copy_from_slice(s);
        TxInWitness::BasicRedeem(sign)
    };
    let schnorrsig = sign_2of2_schnorr(secp, message, &sk1, &sk2)?;
    sk1.0.zeroize();
    sk2.0.zeroize();

    Ok(sigt
        .iter()
        .map(|x| match x {
            SigType::ECDSA => ecsig.clone(),
            SigType::Schnorr => schnorrsig.clone(),
        })
        .collect())
}

/// Generate a TX
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * storage - abstraction over encrypted secrets storage
///
fn gen_tx(matches: &ArgMatches, storage: &SimpleKeyStorage) -> ExecResult {
    if let Some(name) = matches.value_of("name").map(String::from) {
        let chain_id = match matches.value_of("chain_id") {
            Some(x) => {
                let cid = hex::decode(&x)?;
                cid[0]
            }
            _ => {
                return Err(Error::ExecError("missing chain id".to_string()));
            }
        };
        let attr = TxAttributes::new(chain_id);
        let mut tx = Tx::default();
        tx.attributes = attr;
        let mut required_sigs = Vec::new();
        let inputs = check_tupled_args(matches, 3, "inputs")?;
        let mut ichunks = inputs.chunks_exact(3);
        for input in ichunks {
            let txid = hex::decode(&input[0])?;
            if txid.len() != HASH_SIZE_256 {
                return Err(Error::ExecError(
                    "incorrect txid length in input".to_string(),
                ));
            }
            let ind = input[1].parse::<usize>()?;
            match input[2].as_ref() {
                "ecdsa" => required_sigs.push(SigType::ECDSA),
                "schnorr" => required_sigs.push(SigType::Schnorr),
                _ => {
                    return Err(Error::ExecError("unknown signature type".to_string()));
                }
            }
            let mut txids = [0; HASH_SIZE_256];
            txids.copy_from_slice(&txid);
            tx.add_input(TxoPointer::new(txids, ind));
        }
        let outputs = check_tupled_args(matches, 3, "outputs")?;
        let mut ochunks = outputs.chunks_exact(3);
        for output in ochunks {
            let address = hex::decode(&output[1])?;
            let amount = output[2].parse::<Coin>()?;

            match output[0].as_ref() {
                "redeem" => {
                    if address.len() != REDEEM_ADDRESS_BYTES {
                        return Err(Error::ExecError(
                            "incorrect redeem address length in output".to_string(),
                        ));
                    }
                    let mut addr = [0; REDEEM_ADDRESS_BYTES];
                    addr.copy_from_slice(&address);
                    tx.add_output(TxOut::new(ExtendedAddr::BasicRedeem(addr), amount));
                }
                "tree" => {
                    if address.len() != HASH_SIZE_256 {
                        return Err(Error::ExecError(
                            "incorrect tree address length in output".to_string(),
                        ));
                    }
                    let mut addr = [0; HASH_SIZE_256];
                    addr.copy_from_slice(&address);
                    tx.add_output(TxOut::new(ExtendedAddr::OrTree(addr), amount));
                }
                _ => {
                    return Err(Error::ExecError("unknown output address type".to_string()));
                }
            }
        }

        let sigs = get_sig_witnesses(
            name,
            required_sigs,
            &mut tx,
            matches.value_of("extra_view"),
            storage,
        )?;
        let txa = TxAux::new(tx, sigs.into());
        println!("Txid: {}", hex::encode(&txa.tx.id()));
        println!("Tx: {}", hex::encode(&to_vec_packed(&txa)?));
        Ok(())
    } else {
        Err(Error::ExecError("key name not provided".to_string()))
    }
}

enum SigType {
    ECDSA,
    Schnorr,
}

/// Returns 2-of-2 (view+spend keys) agg/combined Schnorr signature witness
///
/// # Arguments:
///
/// * secp - Secp256k1 context with signing capabilities
/// * message - msg to sign (blake2s hash / txid)
/// * sk1 - ref to spend private key
/// * sk2 - ref to view private key
///
fn sign_2of2_schnorr(
    secp: Secp256k1,
    message: Message,
    sk1: &SecretKey,
    sk2: &SecretKey,
) -> Result<TxInWitness, Error> {
    // TODO: "All aggsig-related api functions need review and are subject to change."
    // TODO: migrate to https://github.com/ElementsProject/secp256k1-zkp/pull/35
    // WARNING: secp256k1-zkp was/is highly experimental, its implementation should be verified or replaced by more stable and audited library (when available)

    let pk1 = PublicKey::from_secret_key(&secp, sk1)?;
    let pk2 = PublicKey::from_secret_key(&secp, sk2)?;
    let secnonce_1 = export_secnonce_single(&secp)?;
    let secnonce_2 = export_secnonce_single(&secp)?;
    let pubnonce_2 = PublicKey::from_secret_key(&secp, &secnonce_2)?;
    let mut nonce_sum = pubnonce_2.clone();
    nonce_sum.add_exp_assign(&secp, &secnonce_1)?;
    let mut pk_sum = pk2.clone();
    pk_sum.add_exp_assign(&secp, sk1)?;
    let sig1 = sign_single(
        &secp,
        &message,
        sk1,
        Some(&secnonce_1),
        None,
        Some(&nonce_sum),
        Some(&pk_sum),
        Some(&nonce_sum),
    )?;
    let sig2 = sign_single(
        &secp,
        &message,
        sk2,
        Some(&secnonce_2),
        None,
        Some(&nonce_sum),
        Some(&pk_sum),
        Some(&nonce_sum),
    )?;
    let sig = add_signatures_single(&secp, vec![&sig1, &sig2], &nonce_sum)?;
    let pk = PublicKey::from_combination(&secp, vec![&pk1, &pk2])?;

    Ok(TxInWitness::TreeSig(
        pk_to_raw(&secp, pk),
        sig_to_raw(&secp, sig),
        vec![],
    ))
}
