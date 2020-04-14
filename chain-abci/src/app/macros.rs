//! Construct different buffered stores from `ChainNodeApp`.
//! Ideally these should be methods of `ChainNodeApp`, but that borrow check don't allow that,
//! because methods will need to retain the whole reference of `self` rather than individual fields.
macro_rules! staking_store {
    ($app:expr, $version:expr) => {
        chain_storage::jellyfish::StakingBufferStore::new(
            chain_storage::jellyfish::StakingGetter::new(&$app.storage, $version),
            &mut $app.staking_buffer,
        )
    };
    ($app:expr, $version:expr, $buffer_type:expr) => {
        chain_storage::jellyfish::StakingBufferStore::new(
            chain_storage::jellyfish::StakingGetter::new(&$app.storage, $version),
            match $buffer_type {
                crate::app::app_init::BufferType::Consensus => &mut $app.staking_buffer,
                crate::app::app_init::BufferType::Mempool => &mut $app.mempool_staking_buffer,
            },
        )
    };
}

macro_rules! staking_getter {
    ($app:expr, $version:expr) => {
        chain_storage::jellyfish::StakingBufferGetter::new(
            chain_storage::jellyfish::StakingGetter::new(&$app.storage, $version),
            &$app.staking_buffer,
        )
    };
    ($app:expr, $version:expr, $buffer_type:expr) => {
        chain_storage::jellyfish::StakingBufferGetter::new(
            chain_storage::jellyfish::StakingGetter::new(&$app.storage, $version),
            match $buffer_type {
                crate::app::app_init::BufferType::Consensus => &$app.staking_buffer,
                crate::app::app_init::BufferType::Mempool => &$app.mempool_staking_buffer,
            },
        )
    };
}

macro_rules! kv_store {
    ($app:expr) => {
        chain_storage::buffer::BufferStore::new(&$app.storage, &mut $app.kv_buffer)
    };
    ($app:expr, $buffer_type:expr) => {
        chain_storage::buffer::BufferStore::new(
            &$app.storage,
            match $buffer_type {
                crate::app::app_init::BufferType::Consensus => &mut $app.kv_buffer,
                crate::app::app_init::BufferType::Mempool => &mut $app.mempool_kv_buffer,
            },
        )
    };
}
