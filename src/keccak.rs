//! Native Keccak-f[1600] and SHAKE256 with round-state access for circuits.

use zeroize::Zeroizing;

/// SHAKE256's rate in bytes.
pub const RATE_BYTES: usize = 136;

/// Keccak-f[1600] round constants.
pub const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Keccak-f[1600] rho rotation offsets, indexed by `x + 5*y`.
pub const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// A Keccak state of 25 little-endian 64-bit lanes.
pub type State = [u64; 25];

/// Apply one Keccak-f[1600] round.
#[must_use]
pub fn round(input: &State, round_constant: u64) -> State {
    let mut columns = [0u64; 5];
    for (x, column) in columns.iter_mut().enumerate() {
        *column = input[x] ^ input[x + 5] ^ input[x + 10] ^ input[x + 15] ^ input[x + 20];
    }
    let mut theta = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            theta[x + 5 * y] =
                input[x + 5 * y] ^ columns[(x + 4) % 5] ^ columns[(x + 1) % 5].rotate_left(1);
        }
    }
    let mut permuted = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            let source = x + 5 * y;
            let target_x = y;
            let target_y = (2 * x + 3 * y) % 5;
            permuted[target_x + 5 * target_y] = theta[source].rotate_left(RHO[source]);
        }
    }
    let mut output = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            output[x + 5 * y] = permuted[x + 5 * y]
                ^ (!permuted[(x + 1) % 5 + 5 * y] & permuted[(x + 2) % 5 + 5 * y]);
        }
    }
    output[0] ^= round_constant;
    output
}

/// Apply Keccak-f[1600].
#[must_use]
pub fn keccak_f(mut state: State) -> State {
    for round_constant in RC {
        state = round(&state, round_constant);
    }
    state
}

/// XOR one SHAKE256 rate block into a state.
pub fn absorb_block(state: &mut State, block: &[u8; RATE_BYTES]) {
    let (lanes, remainder) = block.as_chunks::<8>();
    debug_assert!(remainder.is_empty());
    for (index, lane) in lanes.iter().enumerate() {
        state[index] ^= u64::from_le_bytes(*lane);
    }
}

/// Pad a message shorter than one rate block as SHAKE256.
#[must_use]
pub fn pad_single_block(message: &[u8]) -> [u8; RATE_BYTES] {
    assert!(
        message.len() < RATE_BYTES,
        "message must fit in one padded SHAKE256 rate block"
    );
    let mut block = [0u8; RATE_BYTES];
    block[..message.len()].copy_from_slice(message);
    block[message.len()] ^= 0x1f;
    block[RATE_BYTES - 1] ^= 0x80;
    block
}

/// Compute SHAKE256 for arbitrary input and output lengths.
#[must_use]
pub fn shake256(message: &[u8], output_len: usize) -> Vec<u8> {
    let mut state = Zeroizing::new([0u64; 25]);
    let (blocks, remainder) = message.as_chunks::<RATE_BYTES>();
    for block in blocks {
        absorb_block(&mut state, block);
        *state = keccak_f(*state);
    }
    let final_block = Zeroizing::new(pad_single_block(remainder));
    absorb_block(&mut state, &final_block);
    *state = keccak_f(*state);

    let mut output = vec![0u8; output_len];
    for chunk in output.chunks_mut(RATE_BYTES) {
        for (index, byte) in chunk.iter_mut().enumerate() {
            *byte = state[index / 8].to_le_bytes()[index % 8];
        }
        if chunk.len() == RATE_BYTES {
            *state = keccak_f(*state);
        }
    }
    output
}

/// Read one bit using the circuit's state layout.
#[must_use]
pub fn state_bit(state: &State, index: usize) -> bool {
    (state[index / 64] >> (index % 64)) & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    #[test]
    fn matches_sha3_reference() {
        for (message_len, output_len) in [
            (0usize, 32usize),
            (17, 64),
            (135, 137),
            (136, 32),
            (1000, 39),
        ] {
            let message: Vec<u8> = (0..message_len)
                .map(|i| {
                    u8::try_from((i * 7 + 3) % 256).expect("the test pattern is reduced modulo 256")
                })
                .collect();
            let mut hash = sha3::Shake256::default();
            hash.update(&message);
            let mut expected = vec![0u8; output_len];
            hash.finalize_xof().read(&mut expected);
            assert_eq!(shake256(&message, output_len), expected);
        }
    }
}
