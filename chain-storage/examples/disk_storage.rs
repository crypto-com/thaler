use chain_core::state::account::{StakedState, StakedStateAddress};
use chain_storage::buffer::{flush_kvdb, BufferStore, KVBuffer};
use chain_storage::jellyfish::{put_stakings, Version};
use chain_storage::NUM_COLUMNS;

fn main() {
    let mut args = std::env::args().skip(1);
    let db_path = args.next().unwrap();
    let version: u64 = args.next().unwrap().parse().unwrap();
    let num_stakings: u64 = args.next().unwrap().parse().unwrap();
    let db = kvdb_rocksdb::Database::open(
        &kvdb_rocksdb::DatabaseConfig::with_columns(NUM_COLUMNS),
        &db_path,
    )
    .unwrap();
    let mut buffer = KVBuffer::new();

    for version in 0..version {
        let stakings = (0..num_stakings)
            .map(|i| {
                let mut seed = [0; 20];
                seed[..8].clone_from_slice(&version.to_le_bytes());
                seed[8..16].clone_from_slice(&i.to_le_bytes());
                StakedState::default(StakedStateAddress::BasicRedeem(seed.into()))
            })
            .collect::<Vec<_>>();
        put_stakings(
            &mut BufferStore::new(&db, &mut buffer),
            version as Version,
            stakings.iter(),
        )
        .expect("jellyfish error with in memory storage");
        flush_kvdb(&db, std::mem::take(&mut buffer)).unwrap();
    }
}
