//! Canonical digests for credential, presentation, and request-binding data.

use crate::Error;
use sha3::digest::{ExtendableOutput, Update, XofReader};

const CREDENTIAL_CONTEXT_DOMAIN: &[u8] = b"VOLE-ARC/credential-context/v1";
const PRESENTATION_CONTEXT_DOMAIN: &[u8] = b"VOLE-ARC/presentation-context/v1";
const PRESENTATION_SCOPE_DOMAIN: &[u8] = b"VOLE-ARC/scoped-presentation/v1";
const PRESENTATION_BINDING_DOMAIN: &[u8] = b"VOLE-ARC/presentation-binding/v1";

fn hash_framed(domain: &[u8], components: &[&[u8]]) -> [u8; 32] {
    let mut hash = sha3::Shake256::default();
    hash.update(domain);
    for component in components {
        hash.update(&(component.len() as u64).to_le_bytes());
        hash.update(component);
    }
    let mut output = [0u8; 32];
    hash.finalize_xof().read(&mut output);
    output
}

/// Public information bound into credential issuance.
///
/// This can identify an attestation class or credential epoch. It is
/// independent of [`PresentationContext`], so a long-lived credential may be
/// used across many relying-party and epoch buckets when policy permits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialContext(pub(crate) [u8; 32]);

impl CredentialContext {
    /// Hash arbitrary application data into a canonical credential context.
    #[must_use]
    pub fn new(application_data: &[u8]) -> Self {
        Self(hash_framed(CREDENTIAL_CONTEXT_DOMAIN, &[application_data]))
    }

    /// The canonical 32-byte context digest.
    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        self.0
    }
}

impl Default for CredentialContext {
    fn default() -> Self {
        Self::new(&[])
    }
}

/// One public rate-limit bucket.
///
/// Servers must derive this value from trusted policy. A client-selected
/// context lets the client create a fresh bucket for every request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PresentationContext(pub(crate) [u8; 32]);

impl PresentationContext {
    /// Hash an already-canonical application context into a bucket identifier.
    #[must_use]
    pub fn new(application_data: &[u8]) -> Self {
        Self(hash_framed(
            PRESENTATION_CONTEXT_DOMAIN,
            &[application_data],
        ))
    }

    /// Construct a bucket scoped by relying party, purpose, and optional
    /// epoch.
    ///
    /// Each component is length-framed. Changing any component creates an
    /// independent rate-limit bucket.
    #[must_use]
    pub fn scoped(relying_party: &[u8], purpose: &[u8], epoch: Option<&[u8]>) -> Self {
        let (epoch_presence, epoch) = match epoch {
            Some(epoch) => ([1u8], epoch),
            None => ([0u8], &[][..]),
        };
        Self(hash_framed(
            PRESENTATION_SCOPE_DOMAIN,
            &[relying_party, purpose, &epoch_presence, epoch],
        ))
    }

    /// The canonical 32-byte bucket digest.
    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        self.0
    }
}

/// Public per-request data bound into a presentation proof without changing
/// its rate-limit bucket.
///
/// Use this for a Privacy Pass challenge digest, HTTP request digest, or other
/// anti-replay binding. It is excluded from tag derivation so a new request
/// does not reset the scoped counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PresentationBinding(pub(crate) [u8; 32]);

impl PresentationBinding {
    /// Hash arbitrary request data into a canonical binding.
    #[must_use]
    pub fn new(request_data: &[u8]) -> Self {
        Self(hash_framed(PRESENTATION_BINDING_DOMAIN, &[request_data]))
    }

    /// The canonical 32-byte binding digest.
    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        self.0
    }
}

impl Default for PresentationBinding {
    fn default() -> Self {
        Self::new(&[])
    }
}

/// Server policy for one credential presentation.
///
/// The zero-knowledge statement includes the presentation limit; tag
/// derivation excludes it. Raising the limit extends the same bucket instead
/// of creating a second allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresentationChallenge {
    pub(crate) credential_context: CredentialContext,
    pub(crate) presentation_context: PresentationContext,
    pub(crate) binding: PresentationBinding,
    pub(crate) limit: u32,
}

impl PresentationChallenge {
    /// Construct a challenge. A zero limit is rejected because it admits no
    /// valid hidden nonce.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPresentationLimit`] when `limit` is zero.
    pub fn new(
        credential_context: CredentialContext,
        presentation_context: PresentationContext,
        limit: u32,
        binding: PresentationBinding,
    ) -> Result<Self, Error> {
        if limit == 0 {
            return Err(Error::InvalidPresentationLimit);
        }
        Ok(Self {
            credential_context,
            presentation_context,
            binding,
            limit,
        })
    }

    /// Credential-issuance context required by this challenge.
    #[must_use]
    pub fn credential_context(self) -> CredentialContext {
        self.credential_context
    }

    /// Scoped rate-limit bucket.
    #[must_use]
    pub fn presentation_context(self) -> PresentationContext {
        self.presentation_context
    }

    /// Per-request proof binding.
    #[must_use]
    pub fn binding(self) -> PresentationBinding {
        self.binding
    }

    /// Maximum number of accepted tags from one credential in this bucket.
    #[must_use]
    pub fn limit(self) -> u32 {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_context_frames_components() {
        let first = PresentationContext::scoped(b"ab", b"c", Some(b"d"));
        let second = PresentationContext::scoped(b"a", b"bc", Some(b"d"));
        assert_ne!(first, second);
        assert_ne!(
            PresentationContext::scoped(b"rp", b"login", Some(b"epoch-1")),
            PresentationContext::scoped(b"rp", b"login", Some(b"epoch-2"))
        );
        assert_ne!(
            PresentationContext::scoped(b"rp", b"login", None),
            PresentationContext::scoped(b"rp", b"login", Some(b""))
        );
    }

    #[test]
    fn zero_limit_is_rejected() {
        assert_eq!(
            PresentationChallenge::new(
                CredentialContext::default(),
                PresentationContext::new(b"scope"),
                0,
                PresentationBinding::default(),
            ),
            Err(Error::InvalidPresentationLimit)
        );
    }
}
