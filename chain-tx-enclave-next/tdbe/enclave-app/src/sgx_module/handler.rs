use chain_core::tx::data::input::TxoPointer;
use chain_core::tx::data::TxId;

/// Retrieves all the spent transactions for given transaction IDs
///
/// Note: This is a dummy implementation. FIXME: implement
pub fn get_spent_transaction_outputs(_txids: Vec<TxId>) -> Result<Vec<TxoPointer>, String> {
    Ok(Vec::new())
}

/// Retrieves key package for current node
///
/// Note: This is a dummy implementation. FIXME: implement
pub fn get_key_package() -> Result<Vec<u8>, String> {
    Ok(Vec::new())
}
