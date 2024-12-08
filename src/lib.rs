use anyhow::Result;
use circuit::setup_circuit;
use constants::{C, D};
use errors::HashChainError;
use plonky2::plonk::{circuit_data::CircuitData, proof::ProofWithPublicInputs};
use plonky2_field::goldilocks_field::GoldilocksField;
use proof::build_recursive_proof;

mod circuit;
pub mod constants;
pub mod errors;
pub mod hash_chain;
mod proof;

pub fn recursive_proof(
    depth: usize,
    initial_hash: [GoldilocksField; 4],
) -> Result<(
    CircuitData<GoldilocksField, C, D>,
    ProofWithPublicInputs<GoldilocksField, C, D>,
)> {
    if depth == 0 {
        Err(HashChainError::<GoldilocksField>::InvalidRecursionDepth(
            depth,
        ))?;
    }

    let circuit_setup = setup_circuit(depth)?;

    let adjusted_depth = depth - 1; // for zero-based indexing

    let proof = build_recursive_proof(adjusted_depth, initial_hash, &circuit_setup)?;

    Ok((circuit_setup.circuit_data, proof))
}
