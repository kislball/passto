use std::iter::repeat;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use rand::RngCore;
use passto::{AlgorithmSettings, encode, SaltingAlgorithm};

fn get_random_bytes() -> Vec<u8> {
    let mut buf = repeat(0u8).take(32).collect::<Vec<u8>>();
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut buf);
    buf
}

fn benchmark(c: &mut Criterion) {
    let settings = AlgorithmSettings::default();

    c.bench_function("default", |b| {
        b.iter_batched(
            || {
                (get_random_bytes(), get_random_bytes())
            },
            |data| {
                encode(&data.0, &data.1, &settings).unwrap();
            },
            BatchSize::NumIterations(1_000)
        );
    });

    let mut settings = AlgorithmSettings::default();
    settings.hashing_iterations = 10_000;
    settings.salting_iterations = 10_000;

    c.bench_function("10k 10k", |b| {
        b.iter_batched(
            || {
                (get_random_bytes(), get_random_bytes())
            },
            |data| {
                encode(&data.0, &data.1, &settings).unwrap();
            },
            BatchSize::NumIterations(1_000)
        );
    });

    let mut settings = AlgorithmSettings::default();
    settings.hashing_iterations = 10_000;
    settings.salting_iterations = 10_000;
    settings.salting = SaltingAlgorithm::Zip(5);

    c.bench_function("10k 10k(zip)", |b| {
        b.iter_batched(
            || {
                (get_random_bytes(), get_random_bytes())
            },
            |data| {
                encode(&data.0, &data.1, &settings).unwrap();
            },
            BatchSize::NumIterations(1_000)
        );
    });
}

criterion_group!(bench, benchmark);
criterion_main!(bench);
