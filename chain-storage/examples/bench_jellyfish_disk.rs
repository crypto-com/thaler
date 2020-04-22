use criterion::{criterion_group, criterion_main, Bencher, Criterion};

use chain_core::state::account::StakedStateAddress;
use chain_storage::jellyfish::get_with_proof;
use chain_storage::NUM_COLUMNS;

fn bench_get(b: &mut Bencher) {
    let store = kvdb_rocksdb::Database::open(
        &kvdb_rocksdb::DatabaseConfig::with_columns(NUM_COLUMNS),
        &std::env::var("DBPATH").unwrap_or("/tmp/db".to_owned()),
    )
    .unwrap();
    let address: StakedStateAddress = std::env::var("STAKING_ADDRESS")
        .unwrap_or("0000000000000000000000000000000000000000".to_owned())
        .parse()
        .unwrap();

    b.iter(|| {
        get_with_proof(&store, 0, &address);
    });
}
fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("jellyfish_disk, get_with_proof", bench_get);
}
criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
