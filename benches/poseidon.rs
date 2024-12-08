use core::time::Duration;
use criterion::*;
use ivc_poseidon::hash_chain::{check_hash_chain, generate_random_hash};
use ivc_poseidon::recursive_proof;

criterion_group! {
    name = recursive_snark;
    config = Criterion::default().warm_up_time(Duration::from_millis(3000));
    targets = bench_recursive_snark_prove, bench_recursive_snark_verify
}

criterion_main!(recursive_snark);

fn bench_recursive_snark_prove(c: &mut Criterion) {
    let depths = vec![32];

    for d in depths {
        let mut group = c.benchmark_group(format!("Plonky2-Poseidon-num-steps-{}", d));
        group.sample_size(10);

        group.bench_function("Prove", |b| {
            b.iter(|| {
                let initial_hash = generate_random_hash();

                let (_, proof) = recursive_proof(d, initial_hash).expect("Proof building failed");

                black_box(check_hash_chain(&proof).unwrap());
                ()
            })
        });

        group.finish();
    }
}

fn bench_recursive_snark_verify(c: &mut Criterion) {
    let depths = vec![32];

    for d in depths {
        let mut group = c.benchmark_group(format!("Plonky2-Poseidon-num-steps-{}", d));
        group.sample_size(10);

        let initial_hash = generate_random_hash();

        let (cyclic_circuit_data, proof) =
            recursive_proof(d, initial_hash).expect("Recursive proof building failed");

        group.bench_function("Verify", |b| {
            b.iter(|| {
                cyclic_circuit_data
                    .verify(proof.clone())
                    .expect("Verification failed")
            })
        });

        group.finish();
    }
}
