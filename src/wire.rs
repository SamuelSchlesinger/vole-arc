//! Canonical encodings for protocol and local-state artifacts.

use binary_fields::GF16;

pub(crate) const MAGIC: &[u8; 4] = b"VARC";
pub(crate) const WIRE_VERSION: u8 = 1;

/// Largest individual artifact accepted by a canonical decoder.
pub const MAX_WIRE_BYTES: usize = 32 * 1024 * 1024;

/// Failure to decode or authenticate a canonical artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The byte string is truncated, non-canonical, or has trailing data.
    InvalidEncoding,
    /// The envelope describes a different artifact type.
    WrongArtifact,
    /// The envelope names a different MAYO parameter set.
    WrongParameterSet,
    /// Secret state belongs to a different issuer public key.
    WrongIssuer,
    /// The artifact exceeds [`MAX_WIRE_BYTES`].
    TooLarge,
    /// A decoded local credential failed cryptographic authentication.
    InvalidCredential,
    /// The wire-format version is unsupported.
    UnsupportedVersion,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidEncoding => write!(f, "invalid canonical VOLE-ARC encoding"),
            Self::WrongArtifact => write!(f, "wrong VOLE-ARC artifact type"),
            Self::WrongParameterSet => write!(f, "wrong MAYO parameter set"),
            Self::WrongIssuer => write!(f, "wrong VOLE-ARC issuer"),
            Self::TooLarge => write!(f, "VOLE-ARC artifact exceeds the configured limit"),
            Self::InvalidCredential => write!(f, "decoded credential is not authentic"),
            Self::UnsupportedVersion => write!(f, "unsupported VOLE-ARC wire-format version"),
        }
    }
}

impl std::error::Error for WireError {}

pub(crate) fn header(out: &mut Vec<u8>, artifact: u8, parameter_set: u8) {
    out.extend_from_slice(MAGIC);
    out.push(WIRE_VERSION);
    out.extend_from_slice(&[artifact, parameter_set, 0, 0]);
}

pub(crate) fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("wire component exceeds u32 length");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

pub(crate) fn pack_nibbles(values: &[GF16]) -> Vec<u8> {
    let mut output = Vec::with_capacity(values.len().div_ceil(2));
    for (index, value) in values.iter().enumerate() {
        if index.is_multiple_of(2) {
            output.push(value.to_u8());
        } else {
            *output
                .last_mut()
                .expect("odd nibble follows an even nibble") |= value.to_u8() << 4;
        }
    }
    output
}

pub(crate) struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(input: &'a [u8], artifact: u8, parameter_set: u8) -> Result<Self, WireError> {
        if input.len() > MAX_WIRE_BYTES {
            return Err(WireError::TooLarge);
        }
        let mut decoder = Self { input, offset: 0 };
        if decoder.take(MAGIC.len())? != MAGIC {
            return Err(WireError::InvalidEncoding);
        }
        if decoder.u8()? != WIRE_VERSION {
            return Err(WireError::UnsupportedVersion);
        }
        let actual = decoder.array::<4>()?;
        if actual[0] != artifact {
            return Err(WireError::WrongArtifact);
        }
        if actual[1] != parameter_set {
            return Err(WireError::WrongParameterSet);
        }
        if actual[2..] != [0, 0] {
            return Err(WireError::InvalidEncoding);
        }
        Ok(decoder)
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let end = self
            .offset
            .checked_add(len)
            .filter(|end| *end <= self.input.len())
            .ok_or(WireError::InvalidEncoding)?;
        let output = &self.input[self.offset..end];
        self.offset = end;
        Ok(output)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        self.take(N)?
            .try_into()
            .map_err(|_| WireError::InvalidEncoding)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], WireError> {
        let len = usize::try_from(self.u32()?).map_err(|_| WireError::InvalidEncoding)?;
        self.take(len)
    }

    pub(crate) fn nibbles(&mut self, count: usize) -> Result<Vec<GF16>, WireError> {
        let byte_len = count.checked_add(1).ok_or(WireError::InvalidEncoding)? / 2;
        let bytes = self.take(byte_len)?;
        if count % 2 == 1 && bytes.last().is_some_and(|byte| byte & 0xf0 != 0) {
            return Err(WireError::InvalidEncoding);
        }
        Ok((0..count)
            .map(|index| {
                let byte = bytes[index / 2];
                GF16::new(if index.is_multiple_of(2) {
                    byte & 0x0f
                } else {
                    byte >> 4
                })
            })
            .collect())
    }

    pub(crate) fn finish(self) -> Result<(), WireError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(WireError::InvalidEncoding)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_errors_distinguish_type_suite_and_reserved_bytes() {
        let mut encoded = Vec::new();
        header(&mut encoded, 7, 2);

        assert!(Decoder::new(&encoded, 7, 2).is_ok());
        assert!(matches!(
            Decoder::new(&encoded, 6, 2),
            Err(WireError::WrongArtifact)
        ));
        assert!(matches!(
            Decoder::new(&encoded, 7, 1),
            Err(WireError::WrongParameterSet)
        ));

        encoded[7] = 1;
        assert!(matches!(
            Decoder::new(&encoded, 7, 2),
            Err(WireError::InvalidEncoding)
        ));
    }
}
