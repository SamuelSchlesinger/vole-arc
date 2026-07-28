//! VOLE-ARC relations and native witness generation.
//!
//! A presentation proves knowledge of a signer-authenticated hidden
//! credential secret, a deterministic tag for the public presentation scope
//! and hidden counter, and the bound `counter < presentation_limit`.

use crate::ArcParams;
use crate::keccak::{self, RATE_BYTES, RC, RHO};
use binary_fields::{BinaryField, GF2p128, GF16, embed_gf16};
use mayo::PublicKey as MayoPublicKey;
use std::marker::PhantomData;
use voleith::{Backend, Circuit, QuadFormSystem, SharedQuadForm, VoleithError};
use zeroize::Zeroizing;

pub(crate) const CREDENTIAL_DOMAIN: &[u8] = b"VOLE-ARC/credential/v1";
pub(crate) const SIGNED_CREDENTIAL_DOMAIN: &[u8] = b"VOLE-ARC/signed/v1";
pub(crate) const TAG_DOMAIN: &[u8] = b"VOLE-ARC/tag/v1";
pub(crate) const SALT_BYTES: usize = 32;
const SECRET_BYTES: usize = 32;
const HIDING_NONCE_BYTES: usize = 32;
const PRESENTATION_NONCE_BITS: usize = 32;
const KECCAK_CHECKPOINT_BITS: usize = 6 * 1600;

/// Compact representation of the whipped-MAYO quadratic system.
#[derive(Clone)]
pub(crate) struct MayoFormSystem {
    forms: SharedQuadForm,
}

struct MayoQuadForms<P: ArcParams> {
    system: mayo::WhippedSystem<P>,
}

impl<P: ArcParams> QuadFormSystem for MayoQuadForms<P> {
    fn dimension(&self) -> usize {
        self.system.dimension()
    }

    fn num_equations(&self) -> usize {
        self.system.num_equations()
    }

    fn fold(&self, weights: &[GF2p128]) -> Vec<GF2p128> {
        self.system
            .fold(weights)
            .expect("VOLE backend supplies exactly one weight per MAYO equation")
    }
}

pub(crate) fn mayo_system_and_hash<P: ArcParams>(
    public_key: &MayoPublicKey<P>,
) -> (MayoFormSystem, [u8; 32]) {
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let mut hash = sha3::Shake256::default();
    hash.update(b"VOLE-ARC/mayo-public-key/v1");
    hash.update(&(P::N as u64).to_le_bytes());
    hash.update(&(P::M as u64).to_le_bytes());
    hash.update(&(P::O as u64).to_le_bytes());
    hash.update(&(P::K as u64).to_le_bytes());
    let system = public_key.whipped_system_and_visit_forms(|_, form| {
        hash.update(GF16::slice_as_bytes(form.entries()));
    });
    let mut public_key_hash = [0u8; 32];
    hash.finalize_xof().read(&mut public_key_hash);

    (
        MayoFormSystem {
            forms: SharedQuadForm::new(MayoQuadForms { system }),
        },
        public_key_hash,
    )
}

fn hash_scope(domain: &[u8], parts: &[[u8; 32]]) -> [u8; 32] {
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let mut hash = sha3::Shake256::default();
    hash.update(domain);
    for part in parts {
        hash.update(part);
    }
    let mut output = [0u8; 32];
    hash.finalize_xof().read(&mut output);
    output
}

pub(crate) fn credential_scope(
    issuer_context: &[u8; 32],
    credential_context: &[u8; 32],
) -> [u8; 32] {
    hash_scope(
        b"VOLE-ARC/credential-scope/v1",
        &[*issuer_context, *credential_context],
    )
}

pub(crate) fn presentation_scope(
    issuer_context: &[u8; 32],
    credential_context: &[u8; 32],
    presentation_context: &[u8; 32],
) -> [u8; 32] {
    hash_scope(
        b"VOLE-ARC/presentation-scope/v1",
        &[*issuer_context, *credential_context, *presentation_context],
    )
}

pub(crate) fn credential_message(
    scope: &[u8; 32],
    secret: &[u8; SECRET_BYTES],
    hiding_nonce: &[u8; HIDING_NONCE_BYTES],
) -> Zeroizing<Vec<u8>> {
    let mut message = Zeroizing::new(Vec::with_capacity(
        CREDENTIAL_DOMAIN.len() + 32 + SECRET_BYTES + HIDING_NONCE_BYTES,
    ));
    message.extend_from_slice(CREDENTIAL_DOMAIN);
    message.extend_from_slice(scope);
    message.extend_from_slice(secret);
    message.extend_from_slice(hiding_nonce);
    debug_assert!(message.len() < RATE_BYTES);
    message
}

pub(crate) fn credential_target<P: ArcParams>(
    scope: &[u8; 32],
    secret: &[u8; SECRET_BYTES],
    hiding_nonce: &[u8; HIDING_NONCE_BYTES],
) -> Vec<GF16> {
    let output = Zeroizing::new(keccak::shake256(
        &credential_message(scope, secret, hiding_nonce),
        P::M.div_ceil(2),
    ));
    (0..P::M)
        .map(|index| GF16::new((output[index / 2] >> (4 * (index % 2))) & 0x0f))
        .collect()
}

fn pack_gf16(values: &[GF16]) -> Vec<u8> {
    values
        .chunks(2)
        .map(|pair| pair[0].to_u8() | (pair.get(1).map_or(0, |v| v.to_u8()) << 4))
        .collect()
}

pub(crate) fn signed_credential_message<P: ArcParams>(
    commitment: &[GF16],
    salt: &[u8; SALT_BYTES],
) -> Zeroizing<Vec<u8>> {
    debug_assert_eq!(commitment.len(), P::M);
    let packed = Zeroizing::new(pack_gf16(commitment));
    let mut message = Zeroizing::new(Vec::with_capacity(
        SIGNED_CREDENTIAL_DOMAIN.len() + packed.len() + SALT_BYTES,
    ));
    message.extend_from_slice(SIGNED_CREDENTIAL_DOMAIN);
    message.extend_from_slice(&packed);
    message.extend_from_slice(salt);
    debug_assert!(message.len() < RATE_BYTES);
    message
}

pub(crate) fn signed_credential_target<P: ArcParams>(
    commitment: &[GF16],
    salt: &[u8; SALT_BYTES],
) -> Vec<GF16> {
    let output = Zeroizing::new(keccak::shake256(
        &signed_credential_message::<P>(commitment, salt),
        P::M.div_ceil(2),
    ));
    (0..P::M)
        .map(|index| GF16::new((output[index / 2] >> (4 * (index % 2))) & 0x0f))
        .collect()
}

pub(crate) fn tag_message(
    secret: &[u8; SECRET_BYTES],
    scope: &[u8; 32],
    nonce: u32,
) -> Zeroizing<Vec<u8>> {
    let mut message = Zeroizing::new(Vec::with_capacity(TAG_DOMAIN.len() + SECRET_BYTES + 32 + 4));
    message.extend_from_slice(TAG_DOMAIN);
    message.extend_from_slice(secret);
    message.extend_from_slice(scope);
    message.extend_from_slice(&nonce.to_le_bytes());
    debug_assert!(message.len() < RATE_BYTES);
    message
}

pub(crate) fn derive_tag(secret: &[u8; SECRET_BYTES], scope: &[u8; 32], nonce: u32) -> [u8; 32] {
    keccak::shake256(&tag_message(secret, scope, nonce), 32)
        .try_into()
        .expect("requested exactly 32 tag bytes")
}

fn bytes_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |bit| (byte >> bit) & 1 == 1))
        .collect()
}

fn gf16_bits(values: &[GF16]) -> Vec<bool> {
    values
        .iter()
        .flat_map(|value| (0..4).map(|bit| (value.to_u8() >> bit) & 1 == 1))
        .collect()
}

fn append_bytes_bits(output: &mut Vec<bool>, bytes: &[u8]) {
    output.extend(
        bytes
            .iter()
            .flat_map(|byte| (0..8).map(move |bit| (byte >> bit) & 1 == 1)),
    );
}

fn append_gf16_bits(output: &mut Vec<bool>, values: &[GF16]) {
    output.extend(
        values
            .iter()
            .flat_map(|value| (0..4).map(|bit| (value.to_u8() >> bit) & 1 == 1)),
    );
}

fn append_u32_bits(output: &mut Vec<bool>, value: u32) {
    output.extend((0..PRESENTATION_NONCE_BITS).map(|bit| (value >> bit) & 1 == 1));
}

fn append_less_than_carries(output: &mut Vec<bool>, value: u32, limit: u32) {
    // The carry-out of value + !limit + 1 is one iff value >= limit.
    let mut carry = 1u32;
    for bit in 0..PRESENTATION_NONCE_BITS {
        let a = (value >> bit) & 1;
        let b = (!limit >> bit) & 1;
        carry = (a & b) | (a & carry) | (b & carry);
        output.push(carry == 1);
    }
}

#[cfg(test)]
fn less_than_carries(value: u32, limit: u32) -> Vec<bool> {
    let mut carries = Vec::with_capacity(PRESENTATION_NONCE_BITS);
    append_less_than_carries(&mut carries, value, limit);
    carries
}

fn append_keccak_checkpoints(witness: &mut Vec<bool>, message: &[u8]) {
    let block = Zeroizing::new(keccak::pad_single_block(message));
    let mut state = Zeroizing::new([0u64; 25]);
    keccak::absorb_block(&mut state, &block);
    for (round_index, round_constant) in RC.iter().enumerate() {
        *state = keccak::round(&state, *round_constant);
        if (round_index + 1) % 4 == 0 {
            witness.extend((0..1600).map(|bit| keccak::state_bit(&state, bit)));
        }
    }
}

fn alloc_bits<B: Backend>(backend: &mut B, count: usize) -> Result<Vec<B::Wire>, VoleithError> {
    (0..count).map(|_| backend.witness_bit()).collect()
}

fn constant_bit<B: Backend>(backend: &mut B, bit: bool) -> B::Wire {
    backend.constant(if bit { GF2p128::ONE } else { GF2p128::ZERO })
}

fn constant_bytes<B: Backend>(backend: &mut B, bytes: &[u8]) -> Vec<B::Wire> {
    bytes_bits(bytes)
        .into_iter()
        .map(|bit| constant_bit(backend, bit))
        .collect()
}

fn lift_gf16<B: Backend>(backend: &mut B, bits: &[B::Wire]) -> B::Wire {
    debug_assert_eq!(bits.len(), 4);
    let mut accumulator = backend.constant(GF2p128::ZERO);
    for (bit_index, bit) in bits.iter().enumerate() {
        let basis = embed_gf16(GF16::new(1 << bit_index));
        let term = backend.scale(basis, bit);
        accumulator = backend.add(&accumulator, &term);
    }
    accumulator
}

fn lift_nibbles<B: Backend>(backend: &mut B, bits: &[B::Wire]) -> Vec<B::Wire> {
    debug_assert_eq!(bits.len() % 4, 0);
    bits.chunks(4)
        .map(|nibble| lift_gf16(backend, nibble))
        .collect()
}

fn target_constant_bits<B: Backend>(backend: &mut B, target: &[GF16]) -> Vec<B::Wire> {
    gf16_bits(target)
        .into_iter()
        .map(|bit| constant_bit(backend, bit))
        .collect()
}

fn initial_sponge_state<B: Backend>(backend: &mut B, message: &[B::Wire]) -> Vec<B::Wire> {
    debug_assert_eq!(message.len() % 8, 0);
    debug_assert!(message.len() / 8 < RATE_BYTES);
    let zero = backend.constant(GF2p128::ZERO);
    let one = backend.constant(GF2p128::ONE);
    let mut state = vec![zero; 1600];
    for (destination, source) in state.iter_mut().zip(message.iter()) {
        *destination = source.clone();
    }
    let message_byte = message.len() / 8;
    for bit in 0..8 {
        if (0x1fu8 >> bit) & 1 == 1 {
            state[message_byte * 8 + bit] = one.clone();
        }
    }
    state[RATE_BYTES * 8 - 1] = one;
    state
}

fn keccak_linear_expr<B: Backend>(backend: &mut B, state: &[B::Expr]) -> Vec<B::Expr> {
    let zero = backend.constant(GF2p128::ZERO);
    let zero = backend.wire_expr(&zero);
    let mut columns = vec![zero.clone(); 5 * 64];
    for x in 0..5 {
        for z in 0..64 {
            let mut parity = zero.clone();
            for y in 0..5 {
                parity = backend.expr_add(&parity, &state[64 * (x + 5 * y) + z]);
            }
            columns[64 * x + z] = parity;
        }
    }

    let mut theta = vec![zero; 1600];
    for y in 0..5 {
        for x in 0..5 {
            for z in 0..64 {
                let left = &columns[64 * ((x + 4) % 5) + z];
                let right = &columns[64 * ((x + 1) % 5) + ((z + 63) % 64)];
                let delta = backend.expr_add(left, right);
                theta[64 * (x + 5 * y) + z] =
                    backend.expr_add(&state[64 * (x + 5 * y) + z], &delta);
            }
        }
    }
    theta
}

fn pi_rho_index() -> [usize; 1600] {
    let mut index = [0usize; 1600];
    for y in 0..5 {
        for x in 0..5 {
            let source_lane = x + 5 * y;
            let target_x = y;
            let target_y = (2 * x + 3 * y) % 5;
            let target_lane = target_x + 5 * target_y;
            for z in 0..64 {
                let source_z = (z + 64 - RHO[source_lane] as usize) % 64;
                index[64 * target_lane + z] = 64 * source_lane + source_z;
            }
        }
    }
    index
}

fn keccak_round_expr<B: Backend>(
    backend: &mut B,
    state: &[B::Expr],
    round_constant: u64,
) -> Vec<B::Expr> {
    let theta = keccak_linear_expr(backend, state);
    let permutation = pi_rho_index();
    let one = backend.constant(GF2p128::ONE);
    let one = backend.wire_expr(&one);
    let mut output = Vec::with_capacity(1600);
    for bit_index in 0..1600 {
        let lane = bit_index / 64;
        let z = bit_index % 64;
        let x = lane % 5;
        let y = lane / 5;
        let first = &theta[permutation[64 * (x + 5 * y) + z]];
        let second = &theta[permutation[64 * ((x + 1) % 5 + 5 * y) + z]];
        let third = &theta[permutation[64 * ((x + 2) % 5 + 5 * y) + z]];
        let not_second = backend.expr_add(&one, second);
        let product = backend.expr_mul(&not_second, third);
        let mut bit = backend.expr_add(first, &product);
        if lane == 0 && (round_constant >> z) & 1 == 1 {
            bit = backend.expr_add(&bit, &one);
        }
        output.push(bit);
    }
    output
}

fn shake_degree16<B: Backend>(
    backend: &mut B,
    message: &[B::Wire],
) -> Result<Vec<B::Wire>, VoleithError> {
    let mut state = initial_sponge_state(backend, message);
    for group in 0..(RC.len() / 4) {
        let checkpoint = alloc_bits(backend, 1600)?;
        let mut expression: Vec<B::Expr> =
            state.iter().map(|wire| backend.wire_expr(wire)).collect();
        for round in 0..4 {
            expression = keccak_round_expr(backend, &expression, RC[4 * group + round]);
        }
        for (computed, committed) in expression.iter().zip(checkpoint.iter()) {
            let committed = backend.wire_expr(committed);
            let difference = backend.expr_add(computed, &committed);
            backend.assert_expr_zero(&difference);
        }
        state = checkpoint;
    }
    Ok(state)
}

fn shake_hidden_output<B: Backend>(
    backend: &mut B,
    message: &[B::Wire],
    output_bits: usize,
) -> Result<Vec<B::Wire>, VoleithError> {
    let state = shake_degree16(backend, message)?;
    Ok(state[..output_bits].to_vec())
}

fn shake_assert_output<B: Backend>(
    backend: &mut B,
    message: &[B::Wire],
    expected: &[B::Wire],
) -> Result<(), VoleithError> {
    let state = shake_degree16(backend, message)?;
    for (actual, expected) in state.iter().zip(expected.iter()) {
        let difference = backend.add(actual, expected);
        backend.assert_zero(&difference);
    }
    Ok(())
}

fn credential_wires<B: Backend>(
    backend: &mut B,
    scope: &[u8; 32],
    secret: &[B::Wire],
    hiding_nonce: &[B::Wire],
) -> Vec<B::Wire> {
    let mut message = constant_bytes(backend, CREDENTIAL_DOMAIN);
    message.extend(constant_bytes(backend, scope));
    message.extend(secret.iter().cloned());
    message.extend(hiding_nonce.iter().cloned());
    debug_assert_eq!(message.len() % 8, 0);
    message
}

fn signed_credential_wires<B: Backend>(
    backend: &mut B,
    commitment: &[B::Wire],
    salt: &[B::Wire],
) -> Vec<B::Wire> {
    let mut message = constant_bytes(backend, SIGNED_CREDENTIAL_DOMAIN);
    message.extend(commitment.iter().cloned());
    while !message.len().is_multiple_of(8) {
        message.push(constant_bit(backend, false));
    }
    message.extend(salt.iter().cloned());
    debug_assert_eq!(message.len() % 8, 0);
    message
}

fn tag_wires<B: Backend>(
    backend: &mut B,
    secret: &[B::Wire],
    scope: &[u8; 32],
    nonce: &[B::Wire],
) -> Vec<B::Wire> {
    let mut message = constant_bytes(backend, TAG_DOMAIN);
    message.extend(secret.iter().cloned());
    message.extend(constant_bytes(backend, scope));
    message.extend(nonce.iter().cloned());
    debug_assert_eq!(message.len() % 8, 0);
    message
}

fn assert_u32_less_than<B: Backend>(
    backend: &mut B,
    value: &[B::Wire],
    carries: &[B::Wire],
    limit: u32,
) {
    debug_assert_eq!(value.len(), PRESENTATION_NONCE_BITS);
    debug_assert_eq!(carries.len(), PRESENTATION_NONCE_BITS);

    let one = backend.constant(GF2p128::ONE);
    let mut carry_in = one;
    for bit in 0..PRESENTATION_NONCE_BITS {
        let a = backend.wire_expr(&value[bit]);
        let carry = backend.wire_expr(&carry_in);
        let mut equation = backend.wire_expr(&carries[bit]);
        let b = (!limit >> bit) & 1 == 1;
        if b {
            equation = backend.expr_add(&equation, &a);
        }
        let a_times_carry = backend.expr_mul(&a, &carry);
        equation = backend.expr_add(&equation, &a_times_carry);
        if b {
            equation = backend.expr_add(&equation, &carry);
        }
        backend.assert_expr_zero(&equation);
        carry_in = carries[bit].clone();
    }
    // Final carry = 1 exactly when value >= limit.
    backend.assert_zero(&carry_in);
}

pub(crate) struct IssueCircuit<P: ArcParams> {
    pub credential_scope: [u8; 32],
    pub target: Vec<GF16>,
    pub params: PhantomData<P>,
}

impl<P: ArcParams> IssueCircuit<P> {
    pub(crate) fn witness(
        &self,
        secret: &[u8; SECRET_BYTES],
        hiding_nonce: &[u8; HIDING_NONCE_BYTES],
    ) -> Zeroizing<Vec<bool>> {
        let mut witness = Zeroizing::new(Vec::with_capacity(
            (SECRET_BYTES + HIDING_NONCE_BYTES) * 8 + KECCAK_CHECKPOINT_BITS,
        ));
        append_bytes_bits(&mut witness, secret);
        append_bytes_bits(&mut witness, hiding_nonce);
        append_keccak_checkpoints(
            &mut witness,
            &credential_message(&self.credential_scope, secret, hiding_nonce),
        );
        witness
    }
}

impl<P: ArcParams> Circuit for IssueCircuit<P> {
    fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError> {
        if self.target.len() != P::M {
            return Err(VoleithError::InvalidParameters);
        }
        let secret = alloc_bits(backend, SECRET_BYTES * 8)?;
        let hiding_nonce = alloc_bits(backend, HIDING_NONCE_BYTES * 8)?;
        let message = credential_wires(backend, &self.credential_scope, &secret, &hiding_nonce);
        let target = target_constant_bits(backend, &self.target);
        shake_assert_output(backend, &message, &target)
    }
}

pub(crate) struct PresentationCircuit<'a, P: ArcParams> {
    pub mayo_system: &'a MayoFormSystem,
    pub credential_scope: [u8; 32],
    pub presentation_scope: [u8; 32],
    pub presentation_limit: u32,
    pub tag: [u8; 32],
    pub params: PhantomData<P>,
}

pub(crate) struct PresentationSecrets<'a> {
    pub signature: &'a [GF16],
    pub secret: &'a [u8; SECRET_BYTES],
    pub hiding_nonce: &'a [u8; HIDING_NONCE_BYTES],
    pub salt: &'a [u8; SALT_BYTES],
    pub presentation_nonce: u32,
}

impl<P: ArcParams> PresentationCircuit<'_, P> {
    pub(crate) fn witness(&self, secrets: &PresentationSecrets<'_>) -> Zeroizing<Vec<bool>> {
        let mut witness = Zeroizing::new(Vec::with_capacity(
            4 * P::KN
                + (SECRET_BYTES + HIDING_NONCE_BYTES + SALT_BYTES) * 8
                + 2 * PRESENTATION_NONCE_BITS
                + 3 * KECCAK_CHECKPOINT_BITS,
        ));
        append_gf16_bits(&mut witness, secrets.signature);
        append_bytes_bits(&mut witness, secrets.secret);
        append_bytes_bits(&mut witness, secrets.hiding_nonce);
        append_bytes_bits(&mut witness, secrets.salt);
        append_u32_bits(&mut witness, secrets.presentation_nonce);
        append_less_than_carries(
            &mut witness,
            secrets.presentation_nonce,
            self.presentation_limit,
        );

        let commitment = Zeroizing::new(credential_target::<P>(
            &self.credential_scope,
            secrets.secret,
            secrets.hiding_nonce,
        ));
        append_keccak_checkpoints(
            &mut witness,
            &credential_message(&self.credential_scope, secrets.secret, secrets.hiding_nonce),
        );
        append_keccak_checkpoints(
            &mut witness,
            &signed_credential_message::<P>(&commitment, secrets.salt),
        );
        append_keccak_checkpoints(
            &mut witness,
            &tag_message(
                secrets.secret,
                &self.presentation_scope,
                secrets.presentation_nonce,
            ),
        );
        witness
    }
}

impl<P: ArcParams> Circuit for PresentationCircuit<'_, P> {
    fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError> {
        if self.presentation_limit == 0
            || SIGNED_CREDENTIAL_DOMAIN.len() + P::M.div_ceil(2) + SALT_BYTES >= RATE_BYTES
        {
            return Err(VoleithError::InvalidParameters);
        }

        let signature_bits = alloc_bits(backend, 4 * P::KN)?;
        let signature = lift_nibbles(backend, &signature_bits);
        let secret = alloc_bits(backend, SECRET_BYTES * 8)?;
        let hiding_nonce = alloc_bits(backend, HIDING_NONCE_BYTES * 8)?;
        let salt = alloc_bits(backend, SALT_BYTES * 8)?;
        let presentation_nonce = alloc_bits(backend, PRESENTATION_NONCE_BITS)?;
        let carries = alloc_bits(backend, PRESENTATION_NONCE_BITS)?;

        assert_u32_less_than(
            backend,
            &presentation_nonce,
            &carries,
            self.presentation_limit,
        );

        let credential_message =
            credential_wires(backend, &self.credential_scope, &secret, &hiding_nonce);
        let commitment_bits = shake_hidden_output(backend, &credential_message, 4 * P::M)?;

        let signed_message = signed_credential_wires(backend, &commitment_bits, &salt);
        let signed_target_bits = shake_hidden_output(backend, &signed_message, 4 * P::M)?;
        let signed_target = lift_nibbles(backend, &signed_target_bits);
        backend.assert_quad_form_system(signature, self.mayo_system.forms.clone(), signed_target);

        let tag_message = tag_wires(
            backend,
            &secret,
            &self.presentation_scope,
            &presentation_nonce,
        );
        let expected_tag = constant_bytes(backend, &self.tag);
        shake_assert_output(backend, &tag_message, &expected_tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mayo::{Mayo1, MayoParams};

    #[test]
    fn signed_wrapper_fits_widest_supported_hash_output() {
        assert!(SIGNED_CREDENTIAL_DOMAIN.len() + Mayo1::M.div_ceil(2) + SALT_BYTES < RATE_BYTES);
    }

    #[test]
    fn subtraction_carry_characterizes_strict_range() {
        for limit in [1u32, 2, 3, 255, 256, u32::MAX] {
            for value in [
                0,
                limit.saturating_sub(1),
                limit,
                limit.saturating_add(1),
                u32::MAX,
            ] {
                let final_carry = *less_than_carries(value, limit)
                    .last()
                    .expect("32-bit addition has a carry");
                assert_eq!(final_carry, value >= limit, "{value} < {limit}");
            }
        }
    }

    #[test]
    fn limit_is_not_part_of_tag_scope() {
        let issuer = [1u8; 32];
        let credential = [2u8; 32];
        let context = [3u8; 32];
        let scope = presentation_scope(&issuer, &credential, &context);
        let secret = [4u8; 32];
        assert_eq!(
            derive_tag(&secret, &scope, 0),
            derive_tag(&secret, &scope, 0)
        );
        assert_ne!(
            derive_tag(&secret, &scope, 0),
            derive_tag(&secret, &scope, 1)
        );
    }
}
