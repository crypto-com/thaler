// Fight borrow checker
macro_rules! staking_store {
    ($app:expr, $root:expr) => {
        staking_store!($app, $root, true)
    };
    ($app:expr, $root:expr, $deliver:expr) => {
        chain_storage::buffer::StakingBufferStore::new(
            chain_storage::buffer::StakingGetter::new(&$app.accounts, $root),
            if $deliver {
                &mut $app.staking_buffer
            } else {
                &mut $app.mempool_staking_buffer
            },
        )
    };
}

macro_rules! staking_getter {
    ($app:expr, $root:expr) => {
        staking_getter!($app, $root, true)
    };
    ($app:expr, $root:expr, $deliver:expr) => {
        chain_storage::buffer::StakingBufferGetter::new(
            chain_storage::buffer::StakingGetter::new(&$app.accounts, $root),
            if $deliver {
                &$app.staking_buffer
            } else {
                &$app.mempool_staking_buffer
            },
        )
    };
}

macro_rules! kv_store {
    ($app:expr) => {
        chain_storage::buffer::BufferStore::new(&$app.storage, &mut $app.kv_buffer)
    };
    ($app:expr, $deliver:expr) => {
        chain_storage::buffer::BufferStore::new(
            &$app.storage,
            if $deliver {
                &mut $app.kv_buffer
            } else {
                &mut $app.mempool_kv_buffer
            },
        )
    };
}
