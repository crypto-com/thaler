use super::{request_passphrase, Error, ExecResult, SimpleKeyStorage, NONCE_SIZE};
use blake2::{Blake2s, Digest};
use chain_core::init::address::RedeemAddress;
use clap::ArgMatches;
use miscreant::aead::{Aes128PmacSiv, Algorithm};
use rand::rngs::OsRng;
use rand::RngCore;
use secp256k1::{
    key::{PublicKey, SecretKey},
    Secp256k1,
};
use zeroize::Zeroize;

/// Keypair commands
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * storage - abstraction over encrypted secrets storage
///
pub fn keypair_cmd(matches: &ArgMatches, storage: &SimpleKeyStorage) -> ExecResult {
    match matches.subcommand() {
        ("list", _) => list(storage),
        ("new", Some(sub_m)) => new(sub_m, storage),
        ("display", Some(sub_m)) => display(sub_m, storage),
        _ => Err(Error::ExecError(
            "Invalid keypair subcommand. Use `signer keypair -h` for help".to_string(),
        )),
    }
}

/// List all keypairs
///
/// # Arguments:
///
/// * storage - abstraction over encrypted secrets storage
///
fn list(storage: &SimpleKeyStorage) -> ExecResult {
    let keys = storage.list_keys()?;
    for key in keys.iter() {
        println!("key name: {}", key);
    }
    Ok(())
}

/// Creates a new keypair
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * storage - abstraction over encrypted secrets storage
///
fn new(matches: &ArgMatches, storage: &SimpleKeyStorage) -> ExecResult {
    if let Some(name) = matches.value_of("name").map(String::from) {
        let mut hasher = Blake2s::new();

        println!("! Warning: passphrase can't be restored. Don't forget it !");
        hasher.input(request_passphrase()?);
        let mut passphrase = hasher.result_reset();
        let secp = Secp256k1::new();
        let mut algo = Aes128PmacSiv::new(&passphrase);
        let key1n = format!("{}_spend", name);
        let key2n = format!("{}_view", name);

        let mut rand = OsRng::new()?;
        let mut nonce = [0u8; NONCE_SIZE];
        rand.fill_bytes(&mut nonce);
        let mut key1 = algo.seal(
            &nonce,
            key1n.as_bytes(),
            &SecretKey::new(&secp, &mut rand).0[..],
        );
        key1.extend(&nonce[..]);
        storage.write_key(key1n, &key1)?;
        rand.fill_bytes(&mut nonce);
        let mut key2 = algo.seal(
            &nonce,
            key2n.as_bytes(),
            &SecretKey::new(&secp, &mut rand).0[..],
        );
        key2.extend(&nonce[..]);
        storage.write_key(key2n, &key2)?;
        passphrase.zeroize();
        Ok(())
    } else {
        Err(Error::ExecError("key name not provided".to_string()))
    }
}

enum DisplayType {
    EthSpend,
    EthView,
    BothCombined,
}

/// Displays a keypair
///
/// # Arguments:
///
/// * matches - arguments supplied from command-line
/// * storage - abstraction over encrypted secrets storage
///
fn display(matches: &ArgMatches, storage: &SimpleKeyStorage) -> ExecResult {
    if let Some(name) = matches.value_of("name").map(String::from) {
        let dt = match matches.value_of("type") {
            Some("spend") => Ok(DisplayType::EthSpend),
            Some("view") => Ok(DisplayType::EthView),
            Some("both") => Ok(DisplayType::BothCombined),
            _ => Err(Error::ExecError(
                "unknown display type or display type not provided".to_string(),
            )),
        }?;
        let key1n = format!("{}_spend", name);
        let key2n = format!("{}_view", name);
        let ck1 = storage.get_key(&key1n)?;
        let ck2 = storage.get_key(&key2n)?;
        let nonce1_start = ck1.len() - NONCE_SIZE;
        let nonce2_start = ck2.len() - NONCE_SIZE;
        let secp = Secp256k1::new();
        let mut hasher = Blake2s::new();
        let (pk1, pk2) = {
            hasher.input(request_passphrase()?);
            let mut passphrase = hasher.result_reset();
            let mut algo = Aes128PmacSiv::new(&passphrase);
            let pk1 = PublicKey::from_secret_key(
                &secp,
                &SecretKey::from_slice(
                    &secp,
                    &algo.open(&ck1[nonce1_start..], key1n.as_bytes(), &ck1[..nonce1_start])?,
                )?,
            )?;
            let pk2 = PublicKey::from_secret_key(
                &secp,
                &SecretKey::from_slice(
                    &secp,
                    &algo.open(&ck2[nonce2_start..], key2n.as_bytes(), &ck2[..nonce2_start])?,
                )?,
            )?;
            passphrase.zeroize();
            (pk1, pk2)
        };
        match dt {
            DisplayType::EthSpend => {
                println!("address: {}", RedeemAddress::try_from_pk(&secp, &pk1));
            }
            DisplayType::EthView => {
                println!("address: {}", RedeemAddress::try_from_pk(&secp, &pk2));
            }
            DisplayType::BothCombined => {
                let combined = PublicKey::from_combination(&secp, vec![&pk1, &pk2])?;
                hasher.input(&combined.serialize_vec(&secp, true));
                println!(
                    "address (todo: base58): 0x{}",
                    hex::encode(&hasher.result_reset())
                );
            }
        }
        Ok(())
    } else {
        Err(Error::ExecError("key name not provided".to_string()))
    }
}
