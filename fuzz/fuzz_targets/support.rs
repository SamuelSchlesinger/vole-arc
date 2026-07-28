pub(crate) fn mutate_valid(base: &[u8], input: &[u8]) -> Vec<u8> {
    let mut bytes = base.to_vec();
    if input.is_empty() {
        return bytes;
    }

    let mut prefix = [0u8; 8];
    let prefix_len = input.len().min(prefix.len());
    prefix[..prefix_len].copy_from_slice(&input[..prefix_len]);
    let selector = usize::try_from(u64::from_le_bytes(prefix)).unwrap_or(0);
    match input[0] % 4 {
        0 | 3 => {
            let offset = selector % bytes.len();
            for (index, value) in input.iter().enumerate() {
                let destination = (offset + index) % bytes.len();
                bytes[destination] ^= value | 1;
            }
        }
        1 => {
            bytes.truncate(selector % bytes.len());
        }
        _ => {
            bytes.extend_from_slice(input);
        }
    }
    bytes
}
