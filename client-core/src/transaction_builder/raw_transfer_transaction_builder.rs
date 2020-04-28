//! Builder for building raw transfer transaction
use std::ops::Sub;
use std::slice::Iter;
use std::str::FromStr;
use std::string::ToString;

use parity_scale_codec::{Decode, Encode};

use chain_core::init::coin::{sum_coins, Coin};
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::output::TxOut;
use chain_core::tx::data::{Tx, TxId};
use chain_core::tx::fee::FeeAlgorithm;
use chain_core::tx::witness::{TxInWitness, TxWitness};
use chain_core::tx::{TransactionId, TxAux};
use chain_tx_validation::witness::verify_tx_address;
use chain_tx_validation::{check_inputs_basic, check_outputs_basic};
use client_common::{
    Error, ErrorKind, PublicKey, Result, ResultExt, SignedTransaction, Transaction,
};

use crate::signer::{DummySigner, SignCondition, Signer};
use crate::{TransactionObfuscation, UnspentTransactions};
use chain_core::tx::data::address::ExtendedAddr;

/// Unspent transaction output with witness data
#[derive(Debug, Decode, Encode, Clone)]
pub struct WitnessedUTxO {
    /// which utxo?
    pub prev_txo_pointer: TxoPointer,
    /// utxo
    pub prev_tx_out: TxOut,
    /// signature and merkleproof of rawpubkey
    /// rawpubkey: combinded key of publickeys for multisig
    pub witness: Option<TxInWitness>,
    /// max options -- for determining the merkle proof size estimate in the witness, e.g. 2-of-3 threshold has 3 leaves (each is combined 2-of-2 pubkey)
    pub threshold: u16,
}

impl WitnessedUTxO {
    /// Returns if witness data presents
    pub fn has_witness(&self) -> bool {
        self.witness.is_some()
    }

    /// creates a dummy value
    pub fn dummy() -> Self {
        WitnessedUTxO {
            prev_txo_pointer: TxoPointer::new(Default::default(), Default::default()),
            prev_tx_out: TxOut::new(ExtendedAddr::OrTree([0u8; 32]), Default::default()),
            witness: None,
            threshold: 1,
        }
    }
}

/// When withdraw some coin from an offline wallet(W_A),the struct is build from an
/// `watch-only` wallet(W_B) associated with the offline wallet. We can dump the structure
/// from W_A and load it into the W_B so that W_B can make a signed transaction then send
/// it to online W_A by USB storage or email, W_A then broadcast the signed transaction
#[derive(Debug, Clone, Decode, Encode)]
pub struct UnsignedTransferTransaction {
    /// unspend transactions in wallet
    pub unspent_transactions: UnspentTransactions,
    /// view keys
    pub view_keys: Vec<PublicKey>,
    ///  network id
    pub network_id: u8,
    /// send amount
    pub amount: Coin,
    /// send to address
    pub to_address: ExtendedAddr,
    /// return address of online wallet
    pub return_address: ExtendedAddr,
}

impl ToString for UnsignedTransferTransaction {
    fn to_string(&self) -> String {
        let raw_data = self.encode();
        base64::encode(&raw_data)
    }
}

impl FromStr for UnsignedTransferTransaction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let raw_data = base64::decode(s)
            .map_err(|_e| Error::new(ErrorKind::DecryptionError, "decrypt error"))?;
        let tx = Self::decode(&mut raw_data.as_slice())
            .chain(|| (ErrorKind::DecryptionError, "decrypt error"))?;
        Ok(tx)
    }
}

/// on an isolated offline wallet, signed the UnsignedTransferTransaction
#[derive(Debug, Clone, Decode, Encode)]
pub struct SignedTransferTransaction {
    /// signed transfer transaction
    pub signed_transaction: TxAux,
    /// the return amount of coin
    pub return_amount: Coin,
    /// the used inputs to build the transaction
    pub used_inputs: Vec<TxoPointer>,
}

impl ToString for SignedTransferTransaction {
    fn to_string(&self) -> String {
        let raw_data = self.encode();
        base64::encode(&raw_data)
    }
}

impl FromStr for SignedTransferTransaction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let raw_data = base64::decode(s).chain(|| (ErrorKind::DecryptionError, "decrypt error"))?;
        let tx = Self::decode(&mut raw_data.as_slice())
            .chain(|| (ErrorKind::DecryptionError, "decrypt error"))?;
        Ok(tx)
    }
}

/// Raw transfer transaction data structure
#[derive(Debug, Clone, Decode, Encode)]
pub struct RawTransferTransaction {
    inputs: Vec<WitnessedUTxO>,
    outputs: Vec<TxOut>,
    attributes: TxAttributes,
}

/// Raw transfer transaction builder
#[derive(Debug)]
pub struct RawTransferTransactionBuilder<F>
where
    F: FeeAlgorithm,
{
    raw_transaction: RawTransferTransaction,
    fee_algorithm: F,
}

impl<F> RawTransferTransactionBuilder<F>
where
    F: FeeAlgorithm,
{
    // TODO: Refactor attribute setter/getter to separate methods
    /// Create an instance of raw transfer transaction builder
    pub fn new(attributes: TxAttributes, fee_algorithm: F) -> Self {
        let raw_transaction = RawTransferTransaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            attributes,
        };
        RawTransferTransactionBuilder {
            raw_transaction,
            fee_algorithm,
        }
    }

    /// Create an iterator over inputs
    pub fn iter_inputs(&self) -> Iter<WitnessedUTxO> {
        self.raw_transaction.inputs.iter()
    }

    /// Create an iterator over outputs
    pub fn iter_outputs(&self) -> Iter<TxOut> {
        self.raw_transaction.outputs.iter()
    }

    /// Append output to raw transaction
    /// # Warning
    /// When a new input is appended, any previous witness will be cleared
    /// because transaction id will be changed
    pub fn add_input(&mut self, input: (TxoPointer, TxOut), threshold: u16) {
        self.raw_transaction.inputs.push(WitnessedUTxO {
            prev_txo_pointer: input.0,
            prev_tx_out: input.1,
            threshold,
            witness: None,
        });

        self.clear_witness();
    }

    /// Append output to raw transaction
    /// # Warning
    /// When a new output is appended, any previous witness will be cleared
    /// because transaction id will be changed
    pub fn add_output(&mut self, output: TxOut) {
        self.raw_transaction.outputs.push(output);

        self.clear_witness();
    }

    /// Clear all inputs witness.
    /// # Warning
    /// This operation cannot be reverted.
    pub fn clear_witness(&mut self) {
        for input in self.raw_transaction.inputs.iter_mut() {
            input.witness = None;
        }
    }

    /// Returns current raw transaction inputs length
    pub fn inputs_len(&self) -> usize {
        self.raw_transaction.inputs.len()
    }

    /// Returns current raw transaction outputs length
    pub fn outputs_len(&self) -> usize {
        self.raw_transaction.outputs.len()
    }

    /// Get input at provided index
    pub fn input_at_index(&self, index: usize) -> Result<&WitnessedUTxO> {
        if self.inputs_len() < index {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Input index out of bound",
            ));
        }

        Ok(&self.raw_transaction.inputs[index])
    }

    /// Get output at provided index
    pub fn output_at_index(&self, index: usize) -> Result<&TxOut> {
        if self.outputs_len() < index {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Output index out of bound",
            ));
        }

        Ok(&self.raw_transaction.outputs[index])
    }

    /// Sign all signable inputs with signer
    pub fn sign_all<S>(&mut self, signer: S) -> Result<()>
    where
        S: Signer,
    {
        let tx = Transaction::TransferTransaction(self.to_tx());
        let input_witness_pairs: Vec<(usize, TxInWitness)> = self
            .iter_inputs()
            .enumerate()
            .map(|(i, input)| {
                let signing_addr = &input.prev_tx_out.address;
                if SignCondition::SingleSignUnlock != signer.schnorr_sign_condition(signing_addr)? {
                    return Ok(None);
                }

                let witness = signer.schnorr_sign(&tx, signing_addr)?;

                Ok(Some((i, witness)))
            })
            .collect::<Result<Vec<Option<(usize, TxInWitness)>>>>()?
            .into_iter()
            .filter_map(|x| x)
            .collect();
        for (i, witness) in input_witness_pairs.into_iter() {
            self.add_witness(i, witness)?;
        }

        Ok(())
    }

    /// Add witness data to provided input index
    pub fn add_witness(&mut self, index: usize, witness: TxInWitness) -> Result<()> {
        if index > self.inputs_len() {
            return Err(Error::new(ErrorKind::InvalidInput, "Invalid input index"));
        }

        let output_addr = &self.input_at_index(index)?.prev_tx_out.address;
        verify_tx_address(&witness, &self.tx_id(), output_addr).map_err(|err| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Incorrect signature: {}", err),
            )
        })?;

        self.mut_input_at_index(index)?.witness = Some(witness);

        Ok(())
    }

    /// Get mutable input at provided index
    fn mut_input_at_index(&mut self, index: usize) -> Result<&mut WitnessedUTxO> {
        if self.inputs_len() < index {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Input index out of bound",
            ));
        }

        Ok(&mut self.raw_transaction.inputs[index])
    }

    /// Return the fee paid in this transaction
    /// # Error
    /// Returns error when transaction is incompleted
    pub fn fee(&self) -> Result<Coin> {
        if !self.is_completed() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Missing signature in inputs",
            ));
        }

        self.verify_output_does_not_exceed_input_amount()?;

        let input_value = self.total_input_amount()?;
        let output_value = self.total_output_amount()?;

        Ok(input_value.sub(output_value).unwrap())
    }

    /// Returns required fee of completed transfer transaction according to fee
    /// algorithm
    /// # Error
    /// Returns error when transaction is incompleted
    pub fn required_fee<O>(&self, transaction_obfuscation: O) -> Result<Coin>
    where
        O: TransactionObfuscation,
    {
        if !self.is_completed() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Missing signature in inputs",
            ));
        }
        let fee = self
            .fee_algorithm
            .calculate_for_txaux(&self.to_tx_aux(transaction_obfuscation)?)
            .chain(|| {
                (
                    ErrorKind::IllegalInput,
                    "Fee exceeds maximum allowed amount",
                )
            })?
            .to_coin();

        Ok(fee)
    }

    /// Estimate transaction fee with dummy signatures
    pub fn estimate_fee(&self) -> Result<Coin> {
        let dummy_signer = DummySigner();
        let witness = dummy_signer.schnorr_sign_inputs_len(&self.raw_transaction.inputs)?;
        let tx_aux = dummy_signer.mock_txaux_for_tx(self.to_tx(), witness);
        let estimated_fee = self
            .fee_algorithm
            .calculate_for_txaux(&tx_aux)
            .chain(|| {
                (
                    ErrorKind::IllegalInput,
                    "Fee exceeds maximum allowed amount",
                )
            })?
            .to_coin();

        Ok(estimated_fee)
    }

    /// Returns transfer transaction id
    pub fn tx_id(&self) -> TxId {
        self.to_tx().id()
    }

    /// Convert raw transaction to TxAux
    pub fn to_tx_aux<O>(&self, transaction_obfuscation: O) -> Result<TxAux>
    where
        O: TransactionObfuscation,
    {
        self.verify()?;

        let tx = self.to_tx();
        let witness_vec: Vec<TxInWitness> = self
            .iter_inputs()
            .map(|input| input.witness.clone().unwrap())
            .collect();
        let witness = TxWitness::from(witness_vec);
        let signed_transaction = SignedTransaction::TransferTransaction(tx, witness);

        transaction_obfuscation.encrypt(signed_transaction)
    }

    /// Verify the raw transaction is valid
    /// # Error
    /// Returns VerifyError when the transaction is invalid
    pub fn verify(&self) -> Result<()> {
        if !self.is_completed() {
            return Err(Error::new(
                ErrorKind::VerifyError,
                "Missing signature in inputs",
            ));
        }

        self.verify_inputs()?;
        self.verify_outputs()?;
        self.verify_output_does_not_exceed_input_amount()?;
        self.verify_fee()?;
        self.verify_input_witnesses()?;

        Ok(())
    }

    fn verify_inputs(&self) -> Result<()> {
        let inputs: Vec<TxoPointer> = self
            .iter_inputs()
            .map(|input| input.prev_txo_pointer.clone())
            .collect();
        let witness: Vec<TxInWitness> = self
            .iter_inputs()
            .map(|input| input.witness.clone().unwrap())
            .collect();
        let witness = TxWitness::from(witness);
        check_inputs_basic(&inputs, &witness).map_err(|e| {
            Error::new(
                ErrorKind::VerifyError,
                format!("Failed to validate transaction inputs: {}", e),
            )
        })?;

        Ok(())
    }

    fn verify_outputs(&self) -> Result<()> {
        check_outputs_basic(&self.raw_transaction.outputs).map_err(|e| {
            Error::new(
                ErrorKind::VerifyError,
                format!("Failed to validate transaction outputs: {}", e),
            )
        })?;

        Ok(())
    }

    fn verify_output_does_not_exceed_input_amount(&self) -> Result<()> {
        let input_value = self.total_input_amount()?;
        let output_value = self.total_output_amount()?;

        if input_value < output_value {
            return Err(Error::new(ErrorKind::VerifyError, "Insufficient balance"));
        }
        Ok(())
    }

    fn verify_fee(&self) -> Result<()> {
        let fee_expected = self.estimate_fee()?;
        let fee_in_tx = self.fee()?;
        // FIXME: this should be !=, but unit tests don't have proper mocks
        if fee_in_tx < fee_expected {
            let fee_gap = (fee_expected - fee_in_tx).unwrap();
            return Err(Error::new(
                ErrorKind::VerifyError,
                format!("Insufficient fee, need more {:?}", fee_gap),
            ));
        }
        Ok(())
    }

    fn verify_input_witnesses(&self) -> Result<()> {
        let tx_id = self.tx_id();
        for input in self.iter_inputs() {
            let witness = input
                .witness
                .as_ref()
                .chain(|| (ErrorKind::VerifyError, "Missing signature in inputs"))?;
            let output_addr = &input.prev_tx_out.address;
            verify_tx_address(witness, &tx_id, output_addr).map_err(|err| {
                Error::new(
                    ErrorKind::VerifyError,
                    format!("Incorrect signature: {}", err),
                )
            })?;
        }

        Ok(())
    }

    /// Returns the total amount of all inputs
    pub fn total_input_amount(&self) -> Result<Coin> {
        sum_coins(self.iter_inputs().map(|input| input.prev_tx_out.value)).chain(|| {
            (
                ErrorKind::VerifyError,
                "Sum of input values exceeds maximum allowed amount",
            )
        })
    }

    /// Returns the total amount of all outputs
    pub fn total_output_amount(&self) -> Result<Coin> {
        sum_coins(self.iter_outputs().map(|output| output.value)).chain(|| {
            (
                ErrorKind::VerifyError,
                "Sum of output values exceeds maximum allowed amount",
            )
        })
    }

    /// Returns if the all inputs of the transaction are signed
    pub fn is_completed(&self) -> bool {
        self.iter_inputs().all(|input| input.has_witness())
    }

    fn to_tx(&self) -> Tx {
        Tx {
            inputs: self
                .iter_inputs()
                .map(|input| input.prev_txo_pointer.clone())
                .collect(),
            outputs: self.raw_transaction.outputs.clone(),
            attributes: self.raw_transaction.attributes.clone(),
        }
    }

    /// Returns  transaction
    pub fn to_transaction(&self) -> Transaction {
        let transaction = self.to_tx();
        Transaction::TransferTransaction(transaction)
    }

    /// Encode incompleted raw transaction
    pub fn to_incomplete(&self) -> Vec<u8> {
        self.raw_transaction.encode()
    }

    /// Create raw transaction builder from encoded incompleted raw transaction bytes
    pub fn from_incomplete(bytes: Vec<u8>, fee_algorithm: F) -> Result<Self> {
        let raw_transaction =
            RawTransferTransaction::decode(&mut bytes.as_slice()).chain(|| {
                (
                    ErrorKind::DeserializationError,
                    "Unable to deserialize raw transaction",
                )
            })?;

        Ok(RawTransferTransactionBuilder {
            raw_transaction,
            fee_algorithm,
        })
    }
}

#[cfg(test)]
mod raw_transfer_transaction_builder_tests {
    use super::*;

    use rand::random;
    use secp256k1::schnorrsig::SchnorrSignature;

    use chain_core::common::MerkleTree;
    use chain_core::common::H256;
    use chain_core::init::MAX_COIN;
    use chain_core::tx::data::address::ExtendedAddr;
    use chain_core::tx::data::input::TxoSize;
    use chain_core::tx::fee::{LinearFee, Milli};
    use chain_core::tx::witness::tree::RawXOnlyPubkey;
    use chain_core::tx::TxEnclaveAux;
    use client_common::{MultiSigAddress, PrivateKey, PublicKey, Transaction};
    use mock_utils::encrypt;

    use crate::signer::{KeyPairSigner, Signer};
    use crate::unspent_transactions::SelectedUnspentTransactions;

    mod verify {
        use super::*;

        #[test]
        fn should_return_error_when_there_is_unsigned_input() {
            let (_, _, transfer_addr) = create_key_pair_and_transfer_addr();
            let builder = create_2in2out_testing_raw_transaction_builder(transfer_addr);

            let err = builder.verify().unwrap_err();
            assert_eq!(err.kind(), ErrorKind::VerifyError);
            assert_eq!(err.message(), "Missing signature in inputs");
        }

        #[test]
        fn should_return_error_when_input_is_invalid() {
            let attributes = TxAttributes::default();
            let fee_algorithm = create_testing_fee_algorithm();
            let mut builder = RawTransferTransactionBuilder::new(attributes, fee_algorithm);

            builder.add_output(TxOut::new(
                ExtendedAddr::OrTree(random()),
                Coin::new(250).unwrap(),
            ));

            let err = builder.verify().unwrap_err();
            assert_eq!(err.kind(), ErrorKind::VerifyError);
            assert_eq!(
                err.message(),
                "Failed to validate transaction inputs: transaction has no inputs"
            );
        }

        #[test]
        fn should_return_error_when_output_is_invalid() {
            let (private_key, public_key, transfer_addr) = create_key_pair_and_transfer_addr();

            let attributes = TxAttributes::default();
            let fee_algorithm = create_testing_fee_algorithm();
            let mut builder = RawTransferTransactionBuilder::new(attributes, fee_algorithm);

            builder.add_input(
                (
                    TxoPointer::new(random(), 0),
                    TxOut::new(transfer_addr, Coin::new(100).unwrap()),
                ),
                1,
            );
            let tx = builder.to_transaction();

            builder
                .add_witness(0, create_public_key_witness(private_key, public_key, &tx))
                .expect("should add witness to builder");

            let err = builder.verify().unwrap_err();
            assert_eq!(err.kind(), ErrorKind::VerifyError);
            assert_eq!(
                err.message(),
                "Failed to validate transaction outputs: transaction has no outputs"
            );
        }

        #[test]
        fn should_return_error_when_output_exceed_max_coin() {
            let (private_key, public_key, transfer_addr) = create_key_pair_and_transfer_addr();

            let attributes = TxAttributes::default();
            let fee_algorithm = create_testing_fee_algorithm();
            let mut builder = RawTransferTransactionBuilder::new(attributes, fee_algorithm);

            builder.add_input(
                (
                    TxoPointer::new(random(), 0),
                    TxOut::new(transfer_addr, Coin::new(100).unwrap()),
                ),
                1,
            );

            builder.add_output(TxOut::new(
                ExtendedAddr::OrTree(random()),
                Coin::new(MAX_COIN).unwrap(),
            ));
            builder.add_output(TxOut::new(
                ExtendedAddr::OrTree(random()),
                Coin::new(MAX_COIN).unwrap(),
            ));

            builder
                .add_witness(
                    0,
                    create_public_key_witness(private_key, public_key, &builder.to_transaction()),
                )
                .expect("should add witness to builder");

            let err = builder.verify().unwrap_err();
            assert_eq!(err.kind(), ErrorKind::VerifyError);
            assert_eq!(
                err.message(),
                "Sum of output values exceeds maximum allowed amount"
            );
        }

        #[test]
        fn should_return_error_when_output_exceed_input_coin() {
            let (private_key, public_key, transfer_addr) = create_key_pair_and_transfer_addr();

            let attributes = TxAttributes::default();
            let fee_algorithm = create_testing_fee_algorithm();
            let mut builder = RawTransferTransactionBuilder::new(attributes, fee_algorithm);

            builder.add_input(
                (
                    TxoPointer::new(random(), 0),
                    TxOut::new(transfer_addr, Coin::new(100).unwrap()),
                ),
                1,
            );

            builder.add_output(TxOut::new(
                ExtendedAddr::OrTree(random()),
                Coin::new(200).unwrap(),
            ));

            builder
                .add_witness(
                    0,
                    create_public_key_witness(private_key, public_key, &builder.to_transaction()),
                )
                .expect("should add witness to builder");

            let err = builder.verify().unwrap_err();
            assert_eq!(err.kind(), ErrorKind::VerifyError);
            assert_eq!(err.message(), "Insufficient balance");
        }

        #[test]
        fn should_return_ok_when_raw_transaction_is_valid() {
            let (private_key, public_key, transfer_addr) = create_key_pair_and_transfer_addr();
            let mut builder = create_2in2out_testing_raw_transaction_builder(transfer_addr);

            let witness =
                create_public_key_witness(private_key, public_key, &builder.to_transaction());
            let _ = builder.add_witness(0, witness.clone());
            let _ = builder.add_witness(1, witness);

            assert!(builder.verify().is_ok());
        }
    }

    mod add_input {
        use super::*;

        #[test]
        fn should_append_input_to_raw_transaction() {
            let attributes = TxAttributes::default();
            let fee_algorithm = create_testing_fee_algorithm();
            let mut builder = RawTransferTransactionBuilder::new(attributes, fee_algorithm);

            assert_eq!(builder.inputs_len(), 0);

            let input = (
                TxoPointer::new(random(), 0),
                TxOut::new(ExtendedAddr::OrTree(random()), Coin::new(100).unwrap()),
            );
            builder.add_input(input.clone(), 1);

            assert_eq!(builder.inputs_len(), 1);
            assert_eq!(builder.input_at_index(0).unwrap().prev_txo_pointer, input.0);
            assert_eq!(builder.input_at_index(0).unwrap().prev_tx_out, input.1);
        }

        #[test]
        fn should_clear_existing_witness() {
            let (private_key, public_key, transfer_addr) = create_key_pair_and_transfer_addr();
            let mut builder = create_2in2out_testing_raw_transaction_builder(transfer_addr.clone());

            let input_index = 1;
            builder
                .add_witness(
                    input_index,
                    create_public_key_witness(private_key, public_key, &builder.to_transaction()),
                )
                .unwrap();

            assert!(builder.input_at_index(input_index).unwrap().has_witness());

            builder.add_input(
                (
                    TxoPointer::new(random(), 0),
                    TxOut::new(transfer_addr, Coin::new(100).unwrap()),
                ),
                1,
            );

            assert!(!builder.input_at_index(input_index).unwrap().has_witness());
        }
    }

    mod add_output {
        use super::*;

        #[test]
        fn should_append_output_to_raw_transaction() {
            let attributes = TxAttributes::default();
            let fee_algorithm = create_testing_fee_algorithm();
            let mut builder = RawTransferTransactionBuilder::new(attributes, fee_algorithm);

            assert_eq!(builder.outputs_len(), 0);

            let output = TxOut::new(ExtendedAddr::OrTree(random()), Coin::new(50).unwrap());
            builder.add_output(output.clone());

            assert_eq!(builder.outputs_len(), 1);
            assert_eq!(*builder.output_at_index(0).unwrap(), output);
        }

        #[test]
        fn should_clear_existing_witness() {
            let (private_key, public_key, transfer_addr) = create_key_pair_and_transfer_addr();
            let mut builder = create_2in2out_testing_raw_transaction_builder(transfer_addr.clone());

            let input_index = 1;
            builder
                .add_witness(
                    input_index,
                    create_public_key_witness(private_key, public_key, &builder.to_transaction()),
                )
                .unwrap();

            assert!(builder.input_at_index(input_index).unwrap().has_witness());

            builder.add_input(
                (
                    TxoPointer::new(random(), 0),
                    TxOut::new(transfer_addr, Coin::new(100).unwrap()),
                ),
                1,
            );

            assert!(!builder.input_at_index(input_index).unwrap().has_witness());
        }
    }

    mod sign_all {
        use super::*;

        #[test]
        fn should_return_error_when_signer_returns_error_when_sign() {
            struct MockSigner;

            impl Signer for MockSigner {
                fn schnorr_sign(&self, _: &Transaction, _: &ExtendedAddr) -> Result<TxInWitness> {
                    Err(Error::from(ErrorKind::InternalError))
                }

                fn schnorr_sign_transaction(
                    &self,
                    _: &Transaction,
                    _: &SelectedUnspentTransactions<'_>,
                ) -> Result<TxWitness> {
                    unreachable!()
                }

                fn schnorr_sign_condition(&self, _: &ExtendedAddr) -> Result<SignCondition> {
                    Ok(SignCondition::SingleSignUnlock)
                }
            }

            let (_, _, transfer_addr) = create_key_pair_and_transfer_addr();
            let attributes = TxAttributes::default();
            let fee_algorithm = create_testing_fee_algorithm();
            let mut builder = RawTransferTransactionBuilder::new(attributes, fee_algorithm);

            builder.add_input(
                (
                    TxoPointer::new(random(), 0),
                    TxOut::new(transfer_addr.clone(), Coin::new(100).unwrap()),
                ),
                1,
            );
            builder.add_input(
                (
                    TxoPointer::new(random(), 0),
                    TxOut::new(ExtendedAddr::OrTree(random()), Coin::new(200).unwrap()),
                ),
                1,
            );
            builder.add_input(
                (
                    TxoPointer::new(random(), 0),
                    TxOut::new(transfer_addr, Coin::new(200).unwrap()),
                ),
                1,
            );

            builder.add_output(TxOut::new(
                ExtendedAddr::OrTree(random()),
                Coin::new(300).unwrap(),
            ));

            let mock_signer = MockSigner;

            let err = builder.sign_all(mock_signer).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InternalError);
        }

        #[test]
        fn should_return_error_when_signed_witness_is_incorrect() {
            struct MockSigner;

            impl Signer for MockSigner {
                fn schnorr_sign(&self, _: &Transaction, _: &ExtendedAddr) -> Result<TxInWitness> {
                    Ok(create_dummy_witness())
                }

                fn schnorr_sign_transaction(
                    &self,
                    _: &Transaction,
                    _: &SelectedUnspentTransactions<'_>,
                ) -> Result<TxWitness> {
                    unreachable!()
                }

                fn schnorr_sign_condition(&self, _: &ExtendedAddr) -> Result<SignCondition> {
                    Ok(SignCondition::SingleSignUnlock)
                }
            }

            let (_, _, transfer_addr) = create_key_pair_and_transfer_addr();
            let attributes = TxAttributes::default();
            let fee_algorithm = create_testing_fee_algorithm();
            let mut builder = RawTransferTransactionBuilder::new(attributes, fee_algorithm);

            builder.add_input(
                (
                    TxoPointer::new(random(), 0),
                    TxOut::new(transfer_addr.clone(), Coin::new(100).unwrap()),
                ),
                1,
            );
            builder.add_input(
                (
                    TxoPointer::new(random(), 0),
                    TxOut::new(ExtendedAddr::OrTree(random()), Coin::new(200).unwrap()),
                ),
                1,
            );
            builder.add_input(
                (
                    TxoPointer::new(random(), 0),
                    TxOut::new(transfer_addr, Coin::new(200).unwrap()),
                ),
                1,
            );

            builder.add_output(TxOut::new(
                ExtendedAddr::OrTree(random()),
                Coin::new(300).unwrap(),
            ));

            let mock_signer = MockSigner;

            let err = builder.sign_all(mock_signer).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
            assert_eq!(
                err.message(),
                "Incorrect signature: secp: malformed public key"
            )
        }

        #[test]
        fn should_sign_all_signable_inputs_by_signer() {
            let (private_key, public_key, transfer_addr) = create_key_pair_and_transfer_addr();
            let attributes = TxAttributes::default();
            let fee_algorithm = create_testing_fee_algorithm();
            let mut builder = RawTransferTransactionBuilder::new(attributes, fee_algorithm);

            builder.add_input(
                (
                    TxoPointer::new(random(), 0),
                    TxOut::new(transfer_addr.clone(), Coin::new(100).unwrap()),
                ),
                1,
            );
            builder.add_input(
                (
                    TxoPointer::new(random(), 0),
                    TxOut::new(ExtendedAddr::OrTree(random()), Coin::new(200).unwrap()),
                ),
                1,
            );
            builder.add_input(
                (
                    TxoPointer::new(random(), 0),
                    TxOut::new(transfer_addr, Coin::new(200).unwrap()),
                ),
                1,
            );

            builder.add_output(TxOut::new(
                ExtendedAddr::OrTree(random()),
                Coin::new(300).unwrap(),
            ));

            let key_pair_signer = KeyPairSigner::new(private_key, public_key).unwrap();

            builder
                .sign_all(key_pair_signer)
                .expect("sign_all should work");

            assert!(builder.input_at_index(0).unwrap().has_witness());
            assert_eq!(builder.input_at_index(1).unwrap().has_witness(), false);
            assert!(builder.input_at_index(2).unwrap().has_witness());
        }
    }

    mod add_witness {
        use super::*;

        #[test]
        fn should_return_error_when_input_index_does_not_exist() {
            let (_, _, transfer_addr) = create_key_pair_and_transfer_addr();
            let mut builder = create_2in2out_testing_raw_transaction_builder(transfer_addr);

            let out_of_bound_input_index = 5;
            let add_witness_result =
                builder.add_witness(out_of_bound_input_index, create_dummy_witness());
            assert_eq!(
                add_witness_result.expect_err("Invalid input index").kind(),
                ErrorKind::InvalidInput
            );
        }

        #[test]
        fn should_return_error_when_witness_is_incorrect() {
            let (_, _, transfer_addr) = create_key_pair_and_transfer_addr();
            let mut builder = create_2in2out_testing_raw_transaction_builder(transfer_addr);

            let add_witness_result = builder.add_witness(1, create_dummy_witness());

            let err = add_witness_result.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
            assert_eq!(
                err.message(),
                "Incorrect signature: secp: malformed public key"
            );
        }

        #[test]
        fn should_add_witness_to_specified_input_index() {
            let (private_key, public_key, transfer_addr) = create_key_pair_and_transfer_addr();
            let mut builder = create_2in2out_testing_raw_transaction_builder(transfer_addr);

            let input_index = 1;
            let add_witness_result = builder.add_witness(
                input_index,
                create_public_key_witness(private_key, public_key, &builder.to_transaction()),
            );
            assert!(add_witness_result.is_ok());
            assert!(builder
                .input_at_index(input_index)
                .expect("input should exist")
                .has_witness());
        }
    }

    mod is_completed {
        use super::*;

        #[test]
        fn should_return_false_when_one_of_the_input_is_unsigned() {
            let (_, _, transfer_addr) = create_key_pair_and_transfer_addr();
            let raw_transaction_builder =
                create_2in2out_testing_raw_transaction_builder(transfer_addr);

            assert_eq!(raw_transaction_builder.is_completed(), false);
        }

        #[test]
        fn should_return_true_when_all_the_input_is_signed() {
            let (private_key, public_key, transfer_addr) = create_key_pair_and_transfer_addr();
            let mut builder = create_2in2out_testing_raw_transaction_builder(transfer_addr);

            let witness =
                create_public_key_witness(private_key, public_key, &builder.to_transaction());
            builder
                .add_witness(0, witness.clone())
                .expect("should add witness to input index");
            builder
                .add_witness(1, witness)
                .expect("should add witness to input index");

            assert_eq!(builder.is_completed(), true);
        }
    }

    mod fee {
        use super::*;

        #[test]
        fn should_return_error_when_raw_transaction_is_incompleted() {
            let (_, _, transfer_addr) = create_key_pair_and_transfer_addr();
            let builder = create_2in2out_testing_raw_transaction_builder(transfer_addr);

            let err = builder.fee().unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
            assert_eq!(err.message(), "Missing signature in inputs");
        }

        #[test]
        fn should_return_difference_between_inputs_and_outputs() {
            let (private_key, public_key, transfer_addr) = create_key_pair_and_transfer_addr();

            let attributes = TxAttributes::default();
            let fee_algorithm = create_testing_fee_algorithm();
            let mut builder = RawTransferTransactionBuilder::new(attributes, fee_algorithm);

            builder.add_input(
                (
                    TxoPointer::new(random(), 0),
                    TxOut::new(transfer_addr.clone(), Coin::new(100).unwrap()),
                ),
                1,
            );
            builder.add_input(
                (
                    TxoPointer::new(random(), 0),
                    TxOut::new(transfer_addr, Coin::new(200).unwrap()),
                ),
                1,
            );

            builder.add_output(TxOut::new(
                ExtendedAddr::OrTree(random()),
                Coin::new(50).unwrap(),
            ));
            builder.add_output(TxOut::new(
                ExtendedAddr::OrTree(random()),
                Coin::new(100).unwrap(),
            ));

            let witness =
                create_public_key_witness(private_key, public_key, &builder.to_transaction());
            builder
                .add_witness(0, witness.clone())
                .expect("should add witness to input index");
            builder
                .add_witness(1, witness)
                .expect("should add witness to input index");

            let fee = builder.fee().unwrap();

            assert_eq!(fee, Coin::new(150).unwrap());
        }
    }

    mod required_fee {
        use super::*;

        #[test]
        fn should_return_error_when_raw_transaction_is_incompleted() {
            let (_, _, transfer_addr) = create_key_pair_and_transfer_addr();
            let builder = create_2in2out_testing_raw_transaction_builder(transfer_addr);

            let tx_obfuscation = MockTransactionCipher;
            let err = builder.required_fee(tx_obfuscation).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
            assert_eq!(err.message(), "Missing signature in inputs");
        }

        #[test]
        fn estimate_fee_should_be_greater_than_or_equal_to_required_fee() {
            let (private_key, public_key, transfer_addr) = create_key_pair_and_transfer_addr();
            let mut builder = create_2in2out_testing_raw_transaction_builder(transfer_addr);
            let witness =
                create_public_key_witness(private_key, public_key, &builder.to_transaction());
            builder
                .add_witness(0, witness.clone())
                .expect("should add witness to input index");
            builder
                .add_witness(1, witness)
                .expect("should add witness to input index");

            let tx_obfuscation = MockTransactionCipher;
            let required_fee = builder.required_fee(tx_obfuscation).unwrap();
            let estimated_fee = builder.estimate_fee().unwrap();

            assert!(estimated_fee >= required_fee);
        }
    }

    #[test]
    fn test_to_incomplete_from_incomplete_flow() {
        let (private_key, public_key, transfer_addr) = create_key_pair_and_transfer_addr();
        let mut raw_transaction_builder =
            create_2in2out_testing_raw_transaction_builder(transfer_addr);

        raw_transaction_builder
            .add_witness(
                0,
                create_public_key_witness(
                    private_key,
                    public_key,
                    &raw_transaction_builder.to_transaction(),
                ),
            )
            .expect("should add witness to input index");

        let encoded_incomplete_bytes = raw_transaction_builder.to_incomplete();

        let fee_algorithm = create_testing_fee_algorithm();
        assert_eq!(
            RawTransferTransactionBuilder::from_incomplete(
                String::from("hello from rust").into_bytes(),
                fee_algorithm,
            )
            .expect_err("Unable to decode raw transaction bytes")
            .kind(),
            ErrorKind::DeserializationError
        );

        let fee_algorithm = create_testing_fee_algorithm();
        let restored_raw_transaction_builder_result =
            RawTransferTransactionBuilder::from_incomplete(encoded_incomplete_bytes, fee_algorithm);

        assert!(restored_raw_transaction_builder_result.is_ok());

        let restored_raw_transaction_builder = restored_raw_transaction_builder_result.unwrap();
        assert_eq!(restored_raw_transaction_builder.is_completed(), false);
    }

    fn create_2in2out_testing_raw_transaction_builder(
        transfer_addr: ExtendedAddr,
    ) -> RawTransferTransactionBuilder<LinearFee> {
        let attributes = TxAttributes::default();
        let fee_algorithm = create_testing_fee_algorithm();
        let mut builder = RawTransferTransactionBuilder::new(attributes, fee_algorithm);

        builder.add_input(
            (
                TxoPointer::new(random(), 0),
                TxOut::new(transfer_addr.clone(), Coin::new(501).unwrap()),
            ),
            1,
        );
        builder.add_input(
            (
                TxoPointer::new(random(), 0),
                TxOut::new(transfer_addr, Coin::new(500).unwrap()),
            ),
            1,
        );

        builder.add_output(TxOut::new(
            ExtendedAddr::OrTree(random()),
            Coin::new(50).unwrap(),
        ));
        builder.add_output(TxOut::new(
            ExtendedAddr::OrTree(random()),
            Coin::new(250).unwrap(),
        ));

        builder
    }

    fn create_testing_fee_algorithm() -> LinearFee {
        LinearFee::new(Milli::try_new(1, 1).unwrap(), Milli::try_new(1, 1).unwrap())
    }

    fn create_key_pair_and_transfer_addr() -> (PrivateKey, PublicKey, ExtendedAddr) {
        let private_key = PrivateKey::new().expect("should create private key");
        let public_key = PublicKey::from(&private_key);
        let transfer_addr = create_transfer_addr(public_key.clone());

        (private_key, public_key, transfer_addr)
    }

    fn create_public_key_witness(
        private_key: PrivateKey,
        public_key: PublicKey,
        tx: &Transaction,
    ) -> TxInWitness {
        let signing_addr = create_transfer_addr(public_key.clone());

        let signer =
            KeyPairSigner::new(private_key, public_key).expect("should create KeyPairSigner");
        signer
            .schnorr_sign(tx, &signing_addr)
            .expect("should sign transaction id")
    }

    fn create_transfer_addr(public_key: PublicKey) -> ExtendedAddr {
        let require_signers = 1;
        let multi_sig_address = MultiSigAddress::new(
            vec![public_key.clone()],
            public_key.clone(),
            require_signers,
        )
        .expect("should create multi sig address");

        ExtendedAddr::from(multi_sig_address)
    }

    fn create_dummy_witness() -> TxInWitness {
        let raw_pubkey = RawXOnlyPubkey::from([0_u8; 32] as H256);
        let total_pubkeys_len = 2;
        let tree = vec![raw_pubkey.clone(); total_pubkeys_len];
        let merkle_tree = MerkleTree::new(tree);

        let proof = merkle_tree
            .generate_proof(raw_pubkey)
            .expect("generate proof error in mocked merkle tree");
        let mock_signature =
            SchnorrSignature::from_default(&[0_u8; 64]).expect("set mock signature failed");

        TxInWitness::TreeSig(mock_signature, proof)
    }

    #[derive(Debug, Clone)]
    struct MockTransactionCipher;

    impl TransactionObfuscation for MockTransactionCipher {
        fn decrypt(
            &self,
            _transaction_ids: &[TxId],
            _private_key: &PrivateKey,
        ) -> Result<Vec<Transaction>> {
            unreachable!()
        }

        fn encrypt(&self, transaction: SignedTransaction) -> Result<TxAux> {
            match transaction {
                SignedTransaction::TransferTransaction(ref tx, _) => {
                    Ok(TxAux::EnclaveTx(TxEnclaveAux::TransferTx {
                        inputs: tx.inputs.clone(),
                        no_of_outputs: tx.outputs.len() as TxoSize,
                        payload: encrypt(&transaction.clone().into(), [0; 32]),
                    }))
                }
                _ => unreachable!(),
            }
        }
    }
}
