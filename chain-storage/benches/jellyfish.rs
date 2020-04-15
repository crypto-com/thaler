use criterion::{criterion_group, criterion_main, Bencher, Criterion};

use chain_core::state::account::{StakedState, StakedStateAddress};
use chain_storage::buffer::MemStore;
use chain_storage::jellyfish::{get_with_proof, put_stakings, Version};

fn bench_insert_256(b: &mut Bencher) {
    let stakings = (0x00u8..=0x0fu8)
        .map(|version| {
            (0x00u8..=0x0fu8)
                .map(|i| {
                    let mut seed = [0; 20];
                    seed[0] = version;
                    seed[1] = i;
                    StakedState::default(StakedStateAddress::BasicRedeem(seed.into()))
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    b.iter(|| {
        let mut store = MemStore::new();
        for (version, xs) in stakings.iter().enumerate() {
            put_stakings(&mut store, version as Version, xs.iter())
                .expect("jellyfish error with in memory storage");
        }
    });
}

fn bench_insert(b: &mut Bencher) {
    let stakings = (0x00u8..=0x0fu8)
        .map(|version| {
            (0x00u8..=0x0fu8)
                .map(|i| {
                    let mut seed = [0; 20];
                    seed[0] = version;
                    seed[1] = i;
                    StakedState::default(StakedStateAddress::BasicRedeem(seed.into()))
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut store = MemStore::new();
    for (version, xs) in stakings.iter().enumerate() {
        put_stakings(&mut store, version as Version, xs.iter())
            .expect("jellyfish error with in memory storage");
    }
    let mut seed = [0; 20];
    seed[0] = 0x10;
    let stakings = vec![StakedState::default(StakedStateAddress::BasicRedeem(
        seed.into(),
    ))];
    b.iter(|| {
        put_stakings(&mut store, 0x10, stakings.iter()).unwrap();
    });
}

fn bench_get(b: &mut Bencher) {
    let stakings = (0x00u8..=0x0fu8)
        .map(|version| {
            (0x00u8..=0x0fu8)
                .map(|i| {
                    let mut seed = [0; 20];
                    seed[0] = version;
                    seed[1] = i;
                    StakedState::default(StakedStateAddress::BasicRedeem(seed.into()))
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut store = MemStore::new();
    for (version, xs) in stakings.iter().enumerate() {
        put_stakings(&mut store, version as Version, xs.iter())
            .expect("jellyfish error with in memory storage");
    }

    b.iter(|| {
        get_with_proof(
            &store,
            0x0f,
            &stakings.last().unwrap().last().unwrap().address,
        );
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("jellyfish, insert 256", bench_insert_256);
    c.bench_function("jellyfish, insert", bench_insert);
    c.bench_function("jellyfish, get_with_proof", bench_get);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
