use anyhow::{Ok, Result};

use crate::circuit::CircuitSetup;
use crate::constants::{C, D};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::{CircuitData, CommonCircuitData, VerifierCircuitTarget};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;

/// Base Case
/// Sets up the base proof (for the initial hash in the chain).
pub fn setup_base_proof(
    initial_hash: [GoldilocksField; 4],
    cyclic_circuit_data: &CircuitData<GoldilocksField, C, D>,
    common_data: &CommonCircuitData<GoldilocksField, D>,
    condition: BoolTarget,
    inner_cyclic_proof_with_pis: &ProofWithPublicInputsTarget<D>,
    verifier_data_target: &VerifierCircuitTarget,
) -> Result<ProofWithPublicInputs<GoldilocksField, C, D>> {
    let mut pw = PartialWitness::new();
    let initial_hash_pis = initial_hash.into_iter().enumerate().collect();

    pw.set_bool_target(condition, false); // base proof so the condition to do the recursion is set to false
    pw.set_proof_with_pis_target::<C, D>(
        inner_cyclic_proof_with_pis,
        &cyclic_base_proof(
            common_data,
            &cyclic_circuit_data.verifier_only,
            initial_hash_pis,
        ),
    );
    pw.set_verifier_data_target(verifier_data_target, &cyclic_circuit_data.verifier_only);

    cyclic_circuit_data.prove(pw)
}

/// Inductive Step
/// Extends an existing proof for a recursive circuit.
pub fn extend_proof(
    cyclic_circuit_data: &CircuitData<GoldilocksField, C, D>,
    condition: BoolTarget,
    inner_cyclic_proof_with_pis: &ProofWithPublicInputsTarget<D>,
    proof: &ProofWithPublicInputs<GoldilocksField, C, D>,
    verifier_data_target: &VerifierCircuitTarget,
) -> Result<ProofWithPublicInputs<GoldilocksField, C, D>> {
    let mut pw = PartialWitness::new();

    pw.set_bool_target(condition, true);
    pw.set_proof_with_pis_target(inner_cyclic_proof_with_pis, proof);
    pw.set_verifier_data_target(verifier_data_target, &cyclic_circuit_data.verifier_only);

    cyclic_circuit_data.prove(pw)
}

/// Builds the recursive proof for a given depth.
pub fn build_recursive_proof(
    depth: usize,
    initial_hash: [GoldilocksField; 4],
    circuit_setup: &CircuitSetup<GoldilocksField, C, D>,
) -> Result<ProofWithPublicInputs<GoldilocksField, C, D>> {
    let base_proof = setup_base_proof(
        initial_hash,
        &circuit_setup.circuit_data,
        &circuit_setup.common_data,
        circuit_setup.condition,
        &circuit_setup.inner_cyclic_proof_with_pis,
        &circuit_setup.verifier_data_target,
    )?;

    let proof = (0..depth).try_fold(base_proof, |current_proof, _| {
        extend_proof(
            &circuit_setup.circuit_data,
            circuit_setup.condition,
            &circuit_setup.inner_cyclic_proof_with_pis,
            &current_proof,
            &circuit_setup.verifier_data_target,
        )
    })?;

    check_cyclic_proof_verifier_data(
        &proof,
        &circuit_setup.circuit_data.verifier_only,
        &circuit_setup.circuit_data.common,
    )?;

    Ok(proof)
}
