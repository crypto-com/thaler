use aead::{Aead, NewAead};
use generic_array::GenericArray;
use hpke::{
    aead::{AeadCtxR, AeadTag},
    EncappedKey, HpkeError, Marshallable, Unmarshallable,
};
use secrecy::{ExposeSecret, Secret};

use crate::ciphersuite::{AeadKeySize, AeadNonceSize, CipherSuite, Kex, NodeSecret, SecretValue};
use crate::group::GroupInfo;
use crate::key::{HPKEPrivateKey, HPKEPublicKey};
use crate::keypackage::{KeyPackage, KeyPackageSecret};
use crate::message::{EncryptedGroupSecrets, GroupSecret, HPKECiphertext};
use crate::Codec;

pub fn seal_group_secret<CS: CipherSuite>(
    group_secret: &GroupSecret<CS>,
    // FIXME: only for updates/with path secrets?
    // group_context: &GroupContext,
    kp: &KeyPackage<CS>,
) -> Result<EncryptedGroupSecrets<CS>, HpkeError> {
    let mut csprng = rand::thread_rng();
    let recip_pk = &kp.payload.init_key;
    let key_package_hash = CS::hash(&kp.get_encoding());
    let (kem_output, mut context) = hpke::setup_sender::<CS::Aead, CS::Kdf, CS::Kem, _>(
        &hpke::OpModeS::Base,
        recip_pk.kex_pubkey(),
        b"",
        &mut csprng,
    )?;
    let mut group_secret = group_secret.get_encoding();
    let tag = context.seal(&mut group_secret, &[])?; // FIXME ?: &group_context.get_encoding())
    group_secret.extend_from_slice(&tag.marshal());

    Ok(EncryptedGroupSecrets {
        encrypted_group_secrets: HPKECiphertext {
            kem_output: kem_output.marshal(),
            ciphertext: group_secret,
        },
        key_package_hash,
    })
}

pub fn open_group_secret<CS: CipherSuite>(
    encrypted_group_secret: &EncryptedGroupSecrets<CS>,
    // FIXME: group_context: &GroupContext,
    kp_secret: &KeyPackageSecret<CS>,
) -> Result<Option<GroupSecret<CS>>, HpkeError> {
    // FIXME: errors instead of panicking
    let recip_secret = kp_secret.init_private_key.kex_secret();
    let encapped_key = EncappedKey::<Kex<CS>>::unmarshal(
        &encrypted_group_secret.encrypted_group_secrets.kem_output,
    )?;
    let payload_len = encrypted_group_secret
        .encrypted_group_secrets
        .ciphertext
        .len();

    let split_point = payload_len.checked_sub(16).ok_or(HpkeError::InvalidTag)?;
    let (payload, tag_bytes) = encrypted_group_secret
        .encrypted_group_secrets
        .ciphertext
        .split_at(split_point);
    let mut payload = payload.to_vec();
    let tag = AeadTag::<CS::Aead>::unmarshal(tag_bytes)?;

    let mut receiver_ctx = hpke::setup_receiver::<CS::Aead, CS::Kdf, CS::Kem>(
        &hpke::OpModeR::Base,
        &recip_secret,
        &encapped_key,
        b"",
    )?;

    receiver_ctx.open(&mut payload, &[], &tag)?; // FIXME: group context?
    Ok(GroupSecret::read_bytes(&payload))
}

pub fn open_group_info<CS: CipherSuite>(
    encrypted_group_info: &[u8],
    welcome_key: &GenericArray<u8, AeadKeySize<CS>>,
    welcome_nonce: &GenericArray<u8, AeadNonceSize<CS>>,
) -> Result<Option<GroupInfo<CS>>, aead::Error> {
    let aead = <CS::Aead as hpke::aead::Aead>::AeadImpl::new(welcome_key);
    let bytes = aead.decrypt(welcome_nonce, encrypted_group_info)?;
    Ok(GroupInfo::read_bytes(&bytes))
}

pub fn encrypt_group_info<CS: CipherSuite>(
    group_info: &GroupInfo<CS>,
    welcome_key: &GenericArray<u8, AeadKeySize<CS>>,
    welcome_nonce: &GenericArray<u8, AeadNonceSize<CS>>,
) -> Result<Vec<u8>, aead::Error> {
    let aead = <CS::Aead as hpke::aead::Aead>::AeadImpl::new(welcome_key);
    aead.encrypt(welcome_nonce, group_info.get_encoding().as_slice())
}

/// encrypt to public key
pub fn encrypt_path_secret<CS: CipherSuite>(
    secret: &Secret<NodeSecret<CS>>,
    recip_pk: &HPKEPublicKey<CS>,
    aad: &[u8],
) -> Result<HPKECiphertext<CS>, HpkeError> {
    let mut msg = secret.expose_secret().as_ref().to_vec();
    let mut csprng = rand::thread_rng();
    let (kem_output, mut context) = hpke::setup_sender::<CS::Aead, CS::Kdf, CS::Kem, _>(
        &hpke::OpModeS::Base,
        recip_pk.kex_pubkey(),
        b"",
        &mut csprng,
    )?;
    let tag = context.seal(&mut msg, aad)?;
    msg.extend_from_slice(&tag.marshal());
    Ok(HPKECiphertext {
        kem_output: kem_output.marshal(),
        ciphertext: msg,
    })
}

/// decrypt ciphertext
pub fn decrypt_path_secret<CS: CipherSuite>(
    private_key: &HPKEPrivateKey<CS>,
    aad: &[u8],
    ct: &HPKECiphertext<CS>,
) -> Result<Secret<NodeSecret<CS>>, HpkeError> {
    let encapped_key = EncappedKey::<Kex<CS>>::unmarshal(&ct.kem_output)?;
    let mut context = hpke::setup_receiver::<CS::Aead, CS::Kdf, CS::Kem>(
        &hpke::OpModeR::Base,
        private_key.kex_secret(),
        &encapped_key,
        b"",
    )?;
    decrypt_with_context(&mut context, aad, ct)
}

pub fn decrypt_with_context<CS: CipherSuite>(
    context: &mut AeadCtxR<CS::Aead, CS::Kdf, CS::Kem>,
    aad: &[u8],
    ct: &HPKECiphertext<CS>,
) -> Result<Secret<NodeSecret<CS>>, HpkeError> {
    let split_point = ct
        .ciphertext
        .len()
        .checked_sub(16)
        .ok_or(HpkeError::InvalidTag)?;
    let (payload, tag_bytes) = ct.ciphertext.split_at(split_point);
    let tag = AeadTag::<CS::Aead>::unmarshal(tag_bytes)?;
    let mut payload =
        GenericArray::from_exact_iter(payload.iter().copied()).ok_or(HpkeError::InvalidTag)?;

    context.open(&mut payload, aad, &tag)?;
    Ok(Secret::new(SecretValue(payload)))
}
