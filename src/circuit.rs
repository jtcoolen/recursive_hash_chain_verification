use anyhow::{Ok, Result};

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;

use plonky2::field::extension::Extendable;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::AlgebraicHasher;

use crate::constants::{C, D, F};
use crate::errors::CircuitError;

pub(crate) struct CircuitSetup<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub circuit_data: CircuitData<F, C, D>,
    pub common_data: CommonCircuitData<F, D>,
    pub condition: BoolTarget,
    pub inner_cyclic_proof_with_pis: ProofWithPublicInputsTarget<D>,
    pub verifier_data_target: VerifierCircuitTarget,
}

/// Constructs the common circuit data used for recursion.
pub fn common_data<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
) -> CommonCircuitData<F, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    while builder.num_gates() < 1 << 12 {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.build::<C>().common
}

/// Sets up the circuit builder and related data.
pub fn setup_circuit(depth: usize) -> Result<CircuitSetup<GoldilocksField, C, D>> {
    if depth == 0 {
        return Err(CircuitError::InvalidRecursionDepth(depth).into());
    }

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Tracks how many times recursion has occurred
    let counter = builder.add_virtual_public_input();

    let initial_hash_target = builder.add_virtual_hash();
    builder.register_public_inputs(&initial_hash_target.elements);

    let current_hash_in = builder.add_virtual_hash();

    // Hash the current depth and the previous hash (inner_cyclic_latest_hash or initial hash)
    let current_hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
        [[counter].to_vec(), current_hash_in.elements.to_vec()].concat(),
    );
    builder.register_public_inputs(&current_hash_out.elements);

    let verifier_data_target = builder.add_verifier_data_public_inputs();

    let condition = builder.add_virtual_bool_target_safe();

    let one = builder.one();

    let mut common_data = common_data::<F, C, D>();
    common_data.num_public_inputs = builder.num_public_inputs();

    let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);

    // ensures consistency and proper transition between successive proofs
    connect_proof_hash_states(
        &mut builder,
        condition,
        initial_hash_target,
        current_hash_in,
        &inner_cyclic_proof_with_pis,
        counter,
        one,
    )?;

    // If condition is true, verifies the provided inner proof against the current state.
    // If condition is false, uses a dummy verification, allowing the circuit to gracefully
    // handle cases where recursion should not proceed.
    builder.conditionally_verify_cyclic_proof_or_dummy::<C>(
        condition,
        &inner_cyclic_proof_with_pis,
        &common_data,
    )?;

    let circuit_data = builder.build::<C>();

    Ok(CircuitSetup {
        circuit_data,
        common_data,
        condition,
        inner_cyclic_proof_with_pis,
        verifier_data_target,
    })
}

/// Handles the logic of verifying the relationship between the initial
/// hash, the inner proof's latest hash, and the recursive counter. It also sets up the
/// conditions for either continuing recursion with the inner proof's state.
fn connect_proof_hash_states(
    builder: &mut CircuitBuilder<F, D>,
    condition: BoolTarget,
    initial_hash_target: HashOutTarget,
    current_hash_in: HashOutTarget,
    inner_cyclic_proof_with_pis: &ProofWithPublicInputsTarget<D>,
    counter: Target,
    one: Target,
) -> Result<()> {
    let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;

    let inner_cyclic_counter = inner_cyclic_pis[0];
    let inner_cyclic_initial_hash = HashOutTarget::try_from(&inner_cyclic_pis[1..5])
        .map_err(|e| CircuitError::ConversionError(e.to_string()))?;
    let inner_cyclic_latest_hash = HashOutTarget::try_from(&inner_cyclic_pis[5..9])
        .map_err(|e| CircuitError::ConversionError(e.to_string()))?;
    // Copy constraint for the initial_hash of the chain from the inner and outer proofs.
    // This ensures consistency between the initial state of the outer proof and the inner proof
    builder.connect_hashes(initial_hash_target, inner_cyclic_initial_hash);

    // Enables the circuit to either continue with a recursive step (when condition is true)
    // or reset to an initial state (when condition is false).
    let actual_hash_in = HashOutTarget {
        elements: core::array::from_fn(|i| {
            builder.select(
                condition,
                inner_cyclic_latest_hash.elements[i],
                initial_hash_target.elements[i],
            )
        }),
    };
    // copy constraint current_hash_in = actual_hash_in
    builder.connect_hashes(current_hash_in, actual_hash_in);

    // Update counter by adding 1 to inner_cyclic_counter if the condition is true.
    // Otherwise, the counter remains unchanged.
    let new_counter = builder.mul_add(condition.target, inner_cyclic_counter, one);
    builder.connect(counter, new_counter);

    Ok(())
}
