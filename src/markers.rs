//! Protocol errors and VOLE proof-size/latency profiles.

use crate::wire::WireError;
use mayo::{Mayo1, Mayo2, MayoParams};
use voleith::{PARAMS_128, PARAMS_128_BALANCED, PARAMS_128_FAST, Params, VoleithError};

mod sealed {
    pub trait ArcParams {}
}

impl sealed::ArcParams for Mayo1 {}
impl sealed::ArcParams for Mayo2 {}

/// A MAYO parameter set supported by the λ=128 VOLE-ARC suite.
///
/// This trait is sealed to MAYO1 and MAYO2. The VOLE proof layer has λ=128
/// soundness and 128-bit tree seeds. Exposing the dependency's category-3 or
/// category-5 MAYO sets would overstate the security of the combined suite.
pub trait ArcParams: sealed::ArcParams + MayoParams {}

impl ArcParams for Mayo1 {}
impl ArcParams for Mayo2 {}

/// Errors from issuance, presentation, verification, and scoped accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A request is malformed or does not match its retained client state.
    InvalidRequest,
    /// A VOLE-in-the-head proof did not verify.
    InvalidProof,
    /// A returned MAYO preimage does not authenticate the expected target.
    InvalidSignature,
    /// MAYO preimage sampling failed.
    SigningFailed,
    /// A zero presentation limit was supplied.
    InvalidPresentationLimit,
    /// The client-side counter already meets the challenge limit.
    RateLimitReached,
    /// The credential was issued under a different credential context.
    WrongCredentialContext,
    /// The artifact belongs to a different issuer key or protocol context.
    WrongIssuer,
    /// The tag was already accepted in this presentation context.
    TagAlreadyUsed,
    /// The durable tag store could not complete its operation.
    StorageFailure,
    /// The credential has reached the configured local context-state bound.
    TooManyPresentationContexts,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidRequest => write!(f, "invalid VOLE-ARC request"),
            Self::InvalidProof => write!(f, "invalid VOLE-ARC proof"),
            Self::InvalidSignature => write!(f, "invalid MAYO credential authenticator"),
            Self::SigningFailed => write!(f, "MAYO preimage sampling failed"),
            Self::InvalidPresentationLimit => write!(f, "presentation limit must be nonzero"),
            Self::RateLimitReached => write!(f, "scoped presentation limit reached"),
            Self::WrongCredentialContext => write!(f, "credential context mismatch"),
            Self::WrongIssuer => write!(f, "issuer context mismatch"),
            Self::TagAlreadyUsed => write!(f, "scoped presentation tag already used"),
            Self::StorageFailure => write!(f, "tag store operation failed"),
            Self::TooManyPresentationContexts => {
                write!(f, "credential presentation-context state limit reached")
            }
        }
    }
}

impl std::error::Error for Error {}

pub(crate) fn proof_error(_: VoleithError) -> Error {
    Error::InvalidProof
}

/// VOLE tree geometry, trading prover latency against proof size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerformanceProfile {
    /// Smallest proofs, with more seed-tree expansion.
    Compact,
    /// Middle point between proof size and prover latency.
    Balanced,
    /// Lowest built-in prover latency, with a larger correction payload.
    LowLatency,
}

impl PerformanceProfile {
    pub(crate) const fn params(self) -> Params {
        match self {
            Self::Compact => PARAMS_128,
            Self::Balanced => PARAMS_128_BALANCED,
            Self::LowLatency => PARAMS_128_FAST,
        }
    }

    pub(crate) const fn wire_id(self) -> u8 {
        match self {
            Self::Compact => 1,
            Self::Balanced => 2,
            Self::LowLatency => 3,
        }
    }

    pub(crate) fn from_wire_id(id: u8) -> Result<Self, WireError> {
        match id {
            1 => Ok(Self::Compact),
            2 => Ok(Self::Balanced),
            3 => Ok(Self::LowLatency),
            _ => Err(WireError::InvalidEncoding),
        }
    }
}
