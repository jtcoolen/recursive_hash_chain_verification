use anyhow::Result;

use plonky2::hash::hash_types::RichField;
use plonky2::hash::hashing::hash_n_to_hash_no_pad;
use plonky2::hash::poseidon::PoseidonPermutation;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_field::types::Field;
use plonky2_field::{goldilocks_field::GoldilocksField, types::PrimeField64};
use rand::Rng;

use crate::constants::{C, D, F};
use crate::errors::HashChainError;

/// Generates a random hash consisting of four GoldilocksField elements.
pub fn generate_random_hash() -> [GoldilocksField; 4] {
    let mut rng = rand::thread_rng();
    [(); 4].map(|_| GoldilocksField::from_canonical_u64(rng.gen()))
}

/// Computes a hash chain starting from the initial state, applying the hash function n times
/// on the current recursion depth and the current hash.
pub fn hash_chain<F: RichField>(initial_state: [F; 4], n: usize) -> [F; 4] {
    // Use fold to iterate from 1 to n and accumulate the hash state
    (1..=n).fold(initial_state, |current, i| {
        hash_n_to_hash_no_pad::<F, PoseidonPermutation<F>>(
            &[F::from_canonical_u32(i as u32)]
                .iter()
                .chain(current.iter())
                .copied()
                .collect::<Vec<_>>(),
        )
        .elements
    })
}

/// Allows to check that the circuit correctly computes the hash chain
pub fn check_hash_chain(
    proof: &ProofWithPublicInputs<GoldilocksField, C, D>,
) -> Result<(), HashChainError<GoldilocksField>> {
    let counter = proof.public_inputs[0];
    let initial_hash = &proof.public_inputs[1..5];
    let hash = &proof.public_inputs[5..9];

    let initial_hash: [F; 4] = initial_hash
        .try_into()
        .map_err(|_| HashChainError::Other("Failed to convert hash slice.".to_string()))?;
    let hash: [F; 4] = hash
        .try_into()
        .map_err(|_| HashChainError::Other("Failed to convert hash slice.".to_string()))?;

    let expected_hash = hash_chain(initial_hash, counter.to_canonical_u64() as usize);

    if hash != expected_hash {
        return Err(HashChainError::HashVerificationFailed {
            expected: expected_hash.to_vec(),
            actual: hash.to_vec(),
        });
    }

    Ok(())
}
