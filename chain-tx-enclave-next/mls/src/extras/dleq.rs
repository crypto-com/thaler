use std::convert::TryInto;

use secrecy::Secret;

use crate::ciphersuite::{CipherSuite, DefaultCipherSuite, Kex, PublicKey, SecretValue};
use crate::crypto::decrypt_with_context;
use crate::key::{gen_keypair, HPKEPrivateKey, HPKEPublicKey};
use crate::message::HPKECiphertext;
use elliptic_curve::{point::Generator, weierstrass::public_key::FromPublicKey, FromBytes};
use hpke::{
    kex::{Deserializable, Serializable},
    EncappedKey,
};
///! Highly experimental implementation of (honest-verifier) NIZK proof
///! of discrete logarithm equality.
///!
///! ref: https://www.chaum.com/publications/Wallet_Databases.pdf
///! ref: https://blog.cloudflare.com/privacy-pass-the-math/
///! ref: https://github.com/privacypass/challenge-bypass-server#nizk-proofs-of-discrete-log-equality
///!
///! WARNING: highly experimental
///!
///! WARNING: meant to work on prime-order EC ops;
///! *be careful* if this is to be ported to non-prime-order EC ops (e.g. on curve25519)
///! ref: https://www.shiftleft.org/papers/decaf/decaf.pdf
///! (see "1.1 Pitfalls of a cofactor")
use p256::{AffinePoint, ElementBytes, ProjectivePoint, Scalar};
use parity_scale_codec::{Decode, Encode};
use sha2::{Digest, Sha256};
use subtle::{ConstantTimeEq, CtOption};
use zeroize::Zeroize;

/// Information needed by external parties to verify "NACK" claim
/// FIXME: use the official solution when/if ready in the spec
#[derive(Encode, Decode)]
pub struct NackDleqProof {
    /// the computed "r" value
    r_response: [u8; 32],
    /// the intermediate hash
    c_inter_hash: [u8; 32],
    /// revealed shared secret; same size as uncompressed pubkey
    dh: [u8; 65],
}

impl NackDleqProof {
    /// decryption directly using the revealed shared secret
    pub fn decrypt_after_proof<CS: CipherSuite>(
        &self,
        receipient_pk: &HPKEPublicKey<CS>,
        ct: &HPKECiphertext<CS>,
        aad: &[u8],
    ) -> Result<Secret<SecretValue<CS>>, ()> {
        let encapped_key = EncappedKey::<Kex<CS>>::from_bytes(&ct.kem_output).map_err(|_| ())?;
        let shared_secret = hpke::kem::decap_external::<CS::Kem>(
            &self.dh[..],
            &receipient_pk.kex_pubkey(),
            &encapped_key,
        )
        .map_err(|_| ())?;
        let mut context = hpke::setup::derive_receiver_ctx::<CS::Aead, CS::Kdf, CS::Kem>(
            &hpke::OpModeR::Base,
            shared_secret,
            b"",
        );
        decrypt_with_context(&mut context, aad, ct).map_err(|_| ())
    }

    /// ref: https://github.com/mlswg/mls-protocol/issues/21#issuecomment-455392023
    /// in the case that a receiver couldn't get information from Commit/Welcome message
    /// ciphertext, they can disclose the shared secret and DLEQ proof
    /// to show others they couldn't receive the information.
    ///
    /// WARNING: `kem_output` is assumed to be checked with e.g. https://tools.ietf.org/html/rfc8235
    /// (i.e. the sender produced some proof of knowledge of the secret value altogether with the ciphertext
    /// -- the sender secret is currently "hidden" away in HPKE API), so that it's not "tweaked" for compromises
    ///
    /// Side-note: before `get_nack_dleq_proof` is called, the assumption is that the caller already _fully verified_
    /// the Commit message -- e.g. verified that the sender indeed signed it by the valid identity key (remote attested)
    /// -- so from _the point of the other participants_, "Commit" seemed valid.
    /// If this happened (i.e. sender managed to post invalid ciphertext), it's either:
    /// 1) bug in the code here or relevant dependencies
    /// 2) SGX platform was breached.
    /// In the latter case, the "worst case" is that past-transaction data could be read by the attacker.
    /// The attacker could use its node's sealed data instead of tweaking a malformed directpath
    /// and waiting for NACK of the affected node to be broadcasted (assuming the NACK is valid, it'd also
    /// expose the attacker and have its node removed.) -- so checking kem_output with rfc8235 may not make a difference here.
    /// This is assuming no other attacks (beyond compromising historical obfuscated data) are possible
    /// -- !!!TO BE AUDITED!!!
    ///
    /// FIXME: there's a lot of marshalling/unmarshaling due to the current API
    /// + intermediate / secret value zeroing may not be happening
    pub fn get_nack_dleq_proof<CS: CipherSuite>(
        receiver: &HPKEPrivateKey<CS>,
        kem_output: &[u8],
    ) -> Result<Self, ()> {
        let encapped_key = PublicKey::<CS>::from_bytes(kem_output).map_err(|_| ())?;

        // assuming `SetupBaseS` / `SetupBaseR` (used in mls spec draft 10)
        let shared =
            <Kex<CS> as hpke::kex::KeyExchange>::kex(&receiver.kex_secret(), &encapped_key)
                .map_err(|_| ())?;

        // gen_g = encapped_key
        // pub_h = shared
        // gen_m = base point
        // pub_z = receiver pubkey

        // no panic: encapped_key is already parsed/validated by hpke::kex::KeyExchange::PublicKey `from_bytes`
        let g = p256::PublicKey::from_bytes(&encapped_key.to_bytes()).unwrap();
        let gen_g = AffinePoint::from_public_key(&g).unwrap();
        // no panic: shared is already validated by hpke::kex::KeyExchange `kex`
        let h = p256::PublicKey::from_bytes(&shared.to_bytes()).unwrap();
        let pub_h = AffinePoint::from_public_key(&h).unwrap();
        let gen_m = AffinePoint::generator();
        // no panic: HPKEPrivateKey produces valid pubkey
        let z = p256::PublicKey::from_bytes(&receiver.public_key().marshal()).unwrap();
        let pub_z = AffinePoint::from_public_key(&z).unwrap();
        // no panic: HPKEPrivateKey is a valid scalar
        let mut x = Scalar::from_bytes(
            receiver
                .marshal_arr_unsafe()
                .as_slice()
                .try_into()
                .expect("only work with p256 ciphersuit"),
        )
        .unwrap();
        let mproof = Proof::new_p256_sha256(gen_g, pub_h, gen_m, pub_z, &x);
        x.zeroize();
        let proof = mproof?;
        let mut dh = [0u8; 65];
        dh.copy_from_slice(h.as_bytes());
        Ok(NackDleqProof {
            r_response: ElementBytes::from(proof.r_response).into(),
            c_inter_hash: ElementBytes::from(proof.c_inter_hash).into(),
            dh,
        })
    }

    /// to be verifier by other parties:
    /// 1) receiver public key should be known from the keypackage
    /// 2) `sender_kem_output` should be known from some part of the MLS handshake message
    /// TODO: message wrapping the proof will need to contain those information
    /// (i.e. signature with identity key and receiver leaf index +
    /// reference to the invalid part of Commit or Welcome that the parties can retrieve
    /// and verify it's invalid by then using the disclosed `dh` to get HPKE context)
    /// FIXME: there's a lot of marshalling/unmarshaling due to the current API
    pub fn verify<CS: CipherSuite>(
        &self,
        receiver: &HPKEPublicKey<CS>,
        sender_kem_output: &[u8],
    ) -> Result<(), ()> {
        let encapped_key = PublicKey::<CS>::from_bytes(sender_kem_output).map_err(|_| ())?;
        // no panic: encapped_key is already parsed/validated by hpke::kex::KeyExchange::PublicKey `from_bytes`
        let g = p256::PublicKey::from_bytes(&encapped_key.to_bytes()).unwrap();
        let gen_g = AffinePoint::from_public_key(&g).unwrap();
        let h = p256::PublicKey::from_bytes(&self.dh[..]).ok_or(())?;
        let pub_h = AffinePoint::from_public_key(&h);
        // no panic: HPKEPublicKey should be valid
        let z = p256::PublicKey::from_bytes(&receiver.marshal()).unwrap();
        let pub_z = AffinePoint::from_public_key(&z).unwrap();

        let r_response = Scalar::from_bytes(&ElementBytes::from(self.r_response));
        let c_inter_hash = Scalar::from_bytes(&ElementBytes::from(self.c_inter_hash));
        let gen_m = AffinePoint::generator();

        // NOTE: these are subtle::Choice, not booleans
        let error = pub_h.is_none() | r_response.is_none() | c_inter_hash.is_none();

        if error.into() {
            Err(())
        } else {
            let proof = Proof {
                gen_g,
                gen_m,
                pub_h: pub_h.unwrap(),
                pub_z,
                r_response: r_response.unwrap(),
                c_inter_hash: c_inter_hash.unwrap(),
            };
            proof.verify()
        }
    }
}

/// Internal type -- "single letter" naming tries to follow the paper conventions;
/// for a higher level / end-user API, see [NackDleqProof]
struct Proof {
    gen_g: AffinePoint,
    gen_m: AffinePoint,
    pub_h: AffinePoint,
    pub_z: AffinePoint,
    r_response: Scalar,
    c_inter_hash: Scalar,
}

impl Proof {
    /// given h = g^x, z = m^x
    /// prove log_g(h) == log_m(z)
    fn new_p256_sha256(
        gen_g: AffinePoint,
        pub_h: AffinePoint,
        gen_m: AffinePoint,
        pub_z: AffinePoint,
        secret_x: &Scalar,
    ) -> Result<Self, ()> {
        // points are on the same curve + the point at infinity doesn't have the affine representation
        // -> not checking the points
        // TODO: check secret_x or as this is internal API, one assumes it's been validated?
        let g = ProjectivePoint::from(gen_g);
        let m = ProjectivePoint::from(gen_m);
        // random element
        let (s_rand_nonce, _s_pub) = gen_keypair::<DefaultCipherSuite>();
        // no panic: HPKEPrivateKey should produce a valid scalar
        let s_scalar = Scalar::from_bytes(
            s_rand_nonce
                .marshal_arr_unsafe()
                .as_slice()
                .try_into()
                .expect("only work with p256 ciphersuit"),
        )
        .unwrap();
        // (a, b) = (g^s, m^s)
        let ma = (g * &s_scalar).to_affine();
        let mb = (m * &s_scalar).to_affine();
        if (ma.is_none() | mb.is_none()).into() {
            // TODO: is this possible?
            return Err(());
        }
        let a = ma.unwrap();
        let b = mb.unwrap();
        // c = H(g, h, m, z, a, b)
        // note: in the paper, it's H(m, z, a, b)
        let mut hasher = Sha256::new();
        hasher.update(b"dleq proof");
        hasher.update(gen_g.to_pubkey(false).as_bytes());
        hasher.update(pub_h.to_pubkey(false).as_bytes());
        hasher.update(gen_m.to_pubkey(false).as_bytes());
        hasher.update(pub_z.to_pubkey(false).as_bytes());
        hasher.update(a.to_pubkey(false).as_bytes());
        hasher.update(b.to_pubkey(false).as_bytes());
        let c_bytes: [u8; 32] = hasher.finalize().into();

        // TODO: is it safe to use from_bytes_reduced (+ in verification)?
        let mc_inter_hash = Scalar::from_bytes(&ElementBytes::from(c_bytes));
        if mc_inter_hash.is_none().into() {
            return Err(());
        }
        let c_inter_hash = mc_inter_hash.unwrap();
        // note: r = s - cx instead of r = s + cx,
        // so that inversion of c doesn't need to be computed by the verifier
        //
        // (all ops should be `mod p` from Scalar)
        //
        // r = s - cx
        let r_response = s_scalar + &(-c_inter_hash * secret_x);

        Ok(Proof {
            gen_g,
            gen_m,
            pub_h,
            pub_z,
            r_response,
            c_inter_hash,
        })
    }

    fn verify(&self) -> Result<(), ()> {
        // assuming complete proof; points on the same curve + affine representations
        // (not points at infinity)
        // TODO: check scalars or that should be ok, as A, B operations are checked ?

        // prover: c = H(g, h, m, z, a, b)
        // verifier: calculate rG and rM; C' = H(g, h, m, z, rG + cH, rM + cZ)
        // verifier: C ?= C'
        let g_point = ProjectivePoint::from(self.gen_g);
        let m_point = ProjectivePoint::from(self.gen_m);
        let z_point = ProjectivePoint::from(self.pub_z);
        let h_point = ProjectivePoint::from(self.pub_h);

        // a = (g^r)(h^c)
        // A = rG + cH
        let c_h = h_point * &self.c_inter_hash;
        let r_g = g_point * &self.r_response;
        let a_p = &r_g + &c_h;

        // b = (m^r)(z^c)
        // B = rM + cZ
        let c_z = z_point * &self.c_inter_hash;
        let r_m = m_point * &self.r_response;
        let b_p = &r_m + &c_z;

        let ma = a_p.to_affine();
        let mb = b_p.to_affine();
        if (ma.is_none() | mb.is_none()).into() {
            // TODO: is this possible?
            return Err(());
        }
        let a = ma.unwrap();
        let b = mb.unwrap();

        // c' = H(g, h, m, z, a, b) ?= c
        let mut hasher = Sha256::new();
        hasher.update(b"dleq proof");
        hasher.update(self.gen_g.to_pubkey(false).as_bytes());
        hasher.update(self.pub_h.to_pubkey(false).as_bytes());
        hasher.update(self.gen_m.to_pubkey(false).as_bytes());
        hasher.update(self.pub_z.to_pubkey(false).as_bytes());
        hasher.update(a.to_pubkey(false).as_bytes());
        hasher.update(b.to_pubkey(false).as_bytes());
        let c_bytes: [u8; 32] = hasher.finalize().into();

        let c_inter_hash_prime = Scalar::from_bytes(&ElementBytes::from(c_bytes));
        let c_inter_hash = CtOption::new(self.c_inter_hash, 1u8.into());
        if c_inter_hash.ct_eq(&c_inter_hash_prime).into() {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ciphersuite::DefaultCipherSuite as CS;
    use crate::key::gen_keypair;

    fn setup() -> (Scalar, AffinePoint, AffinePoint) {
        let (x, _) = gen_keypair::<CS>();
        let x_scalar =
            Scalar::from_bytes(x.marshal_arr_unsafe().as_slice().try_into().unwrap()).unwrap();
        let (_, g_pub) = gen_keypair::<CS>();
        let (_, m_pub) = gen_keypair::<CS>();

        let g = p256::PublicKey::from_bytes(&g_pub.marshal()).unwrap();
        let gen_g = AffinePoint::from_public_key(&g).unwrap();

        let m = p256::PublicKey::from_bytes(&m_pub.marshal()).unwrap();
        let gen_m = AffinePoint::from_public_key(&m).unwrap();

        (x_scalar, gen_g, gen_m)
    }

    #[test]
    fn test_external_proof() {
        let (receive_secret, receiver_pk) = gen_keypair::<CS>();
        let mut csprng = rand::thread_rng();

        let (kem_output, _) = hpke::setup_sender::<
            hpke::aead::AesGcm128,
            hpke::kdf::HkdfSha256,
            hpke::kem::DhP256HkdfSha256,
            _,
        >(
            &hpke::OpModeS::Base,
            receiver_pk.kex_pubkey(),
            b"",
            &mut csprng,
        )
        .expect("setup sender");

        // assume sender e.g. put invalid content in ciphertext of EncryptedGroupSecrets
        // the receiver can then reveal the shared secret + dleq proof
        let kem_in_mls_payload = kem_output.to_bytes();
        let proof_for_nack =
            NackDleqProof::get_nack_dleq_proof(&receive_secret, &kem_in_mls_payload)
                .expect("valid proof");

        // others can then verify the proof
        assert!(proof_for_nack
            .verify(&receiver_pk, &kem_in_mls_payload)
            .is_ok());
        // and then use the disclosed shared secret to decrypt the ciphertext
        // and verify it's invalid
    }

    #[test]
    fn test_proof_valid() {
        let (x, gen_g, gen_m) = setup();
        let pub_h = ProjectivePoint::from(gen_g.clone()) * &x;
        let pub_z = ProjectivePoint::from(gen_m.clone()) * &x;
        let proof = Proof::new_p256_sha256(
            gen_g,
            pub_h.to_affine().unwrap(),
            gen_m,
            pub_z.to_affine().unwrap(),
            &x,
        )
        .expect("dleq proof");
        assert!(proof.verify().is_ok())
    }

    #[test]
    fn test_proof_invalid() {
        let (x, gen_g, gen_m) = setup();
        let (n, _) = gen_keypair::<CS>();
        let n_scalar =
            Scalar::from_bytes(n.marshal_arr_unsafe().as_slice().try_into().unwrap()).unwrap();

        let pub_h = ProjectivePoint::from(gen_g.clone()) * &x;
        // z = nM instead
        let pub_z = ProjectivePoint::from(gen_m.clone()) * &n_scalar;
        let proof = Proof::new_p256_sha256(
            gen_g,
            pub_h.to_affine().unwrap(),
            gen_m,
            pub_z.to_affine().unwrap(),
            &x,
        )
        .expect("dleq proof");
        assert!(proof.verify().is_err())
    }
}
