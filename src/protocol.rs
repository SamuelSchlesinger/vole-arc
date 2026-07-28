//! Issuance, scoped presentations, verification, and client state.

use crate::circuit::{
    IssueCircuit, MayoFormSystem, PresentationCircuit, PresentationSecrets, SALT_BYTES,
    credential_scope, credential_target, derive_tag, mayo_system_and_hash, presentation_scope,
    signed_credential_target,
};
use crate::context::{CredentialContext, PresentationChallenge, PresentationContext};
use crate::markers::proof_error;
use crate::store::{MemoryTagStore, TagStore};
use crate::wire::{self, Decoder, WireError};
use crate::{ArcParams, Error, PerformanceProfile};
use binary_fields::GF16;
use mayo::{Mayo2, PublicKey as MayoPublicKey, SecretKey as MayoSecretKey};
use rand_core::CryptoRngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use voleith::{Proof, prove, verify};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const ISSUE_STATEMENT: &[u8] = b"VOLE-ARC/issue-statement/v1";
const PRESENTATION_STATEMENT: &[u8] = b"VOLE-ARC/presentation-statement/v1";

/// Maximum application-context length encoded in an issuer key.
pub const MAX_APPLICATION_CONTEXT_BYTES: usize = 4096;

/// Maximum number of presentation-context counters retained in one
/// credential.
///
/// Context state cannot be evicted safely: resetting a counter repeats a tag,
/// harming unlinkability and causing a server-side duplicate. Rotate the
/// credential or use an application-managed state design if this bound is
/// unsuitable.
pub const MAX_PRESENTATION_CONTEXTS: usize = 4096;

const WIRE_PUBLIC_KEY: u8 = 1;
const WIRE_ISSUER_KEY: u8 = 2;
const WIRE_ISSUE_REQUEST: u8 = 3;
const WIRE_ISSUE_RESPONSE: u8 = 4;
const WIRE_PENDING_ISSUE: u8 = 5;
const WIRE_CREDENTIAL: u8 = 6;
const WIRE_PRESENTATION: u8 = 7;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CounterKey([u8; 32]);

impl Borrow<[u8; 32]> for CounterKey {
    fn borrow(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for CounterKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for CounterKey {}

pub(crate) struct PublicInner<P: ArcParams> {
    mayo: MayoPublicKey<P>,
    mayo_system: MayoFormSystem,
    context: [u8; 32],
    profile: PerformanceProfile,
    application_context: Vec<u8>,
}

/// Issuer public key and compact MAYO verification structure.
///
/// Unlike ARC(P-256), this construction makes presentations publicly
/// verifiable.
pub struct PublicKey<P: ArcParams = Mayo2> {
    inner: Arc<PublicInner<P>>,
}

impl<P: ArcParams> Clone for PublicKey<P> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<P: ArcParams> core::fmt::Debug for PublicKey<P> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PublicKey")
            .field("parameter_set", &P::NAME)
            .field("context", &self.inner.context)
            .finish_non_exhaustive()
    }
}

impl<P: ArcParams> PublicKey<P> {
    /// The protocol context binding the key, application domain, parameter
    /// set, protocol version, and VOLE profile.
    #[must_use]
    pub fn context(&self) -> [u8; 32] {
        self.inner.context
    }

    /// VOLE proof-size/latency profile bound into this key.
    #[must_use]
    pub fn performance_profile(&self) -> PerformanceProfile {
        self.inner.profile
    }

    /// Application and key-epoch label bound into this issuer key.
    #[must_use]
    pub fn application_context(&self) -> &[u8] {
        &self.inner.application_context
    }

    /// Encode the public key canonically.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mayo = self.inner.mayo.to_bytes();
        let mut output = Vec::with_capacity(16 + self.inner.application_context.len() + mayo.len());
        wire::header(&mut output, WIRE_PUBLIC_KEY, P::WIRE_ID);
        output.push(self.inner.profile.wire_id());
        wire::put_bytes(&mut output, &self.inner.application_context);
        wire::put_bytes(&mut output, &mayo);
        output
    }

    /// Decode a canonical public key and recompute its derived protocol
    /// context and compact circuit structure.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] when the envelope, suite, profile, application
    /// context, MAYO key, or trailing data is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes, WIRE_PUBLIC_KEY, P::WIRE_ID)?;
        let profile = PerformanceProfile::from_wire_id(decoder.u8()?)?;
        let application_context = decoder.bytes()?;
        if application_context.len() > MAX_APPLICATION_CONTEXT_BYTES {
            return Err(WireError::InvalidEncoding);
        }
        let application_context = application_context.to_vec();
        let mayo = MayoPublicKey::<P>::from_bytes(decoder.bytes()?)
            .map_err(|_| WireError::InvalidEncoding)?;
        decoder.finish()?;
        let (mayo_system, public_key_hash) = mayo_system_and_hash(&mayo);
        let context = derive_issuer_context::<P>(&application_context, &public_key_hash, profile);
        Ok(Self {
            inner: Arc::new(PublicInner {
                mayo,
                mayo_system,
                context,
                profile,
                application_context,
            }),
        })
    }

    /// Start a blind issuance request for a fresh hidden credential secret.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidProof`] if the proof backend cannot construct
    /// the issuance proof.
    pub fn prepare_issue(
        &self,
        credential_context: CredentialContext,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(PendingIssue<P>, IssueRequest<P>), Error> {
        let mut secret = Zeroizing::new([0u8; 32]);
        let mut hiding_nonce = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut secret[..]);
        rng.fill_bytes(&mut hiding_nonce[..]);
        let scope = credential_scope(&self.inner.context, &credential_context.0);
        let commitment = credential_target::<P>(&scope, &secret, &hiding_nonce);
        let circuit = IssueCircuit::<P> {
            credential_scope: scope,
            target: commitment.clone(),
            params: PhantomData,
        };
        let witness = circuit.witness(&secret, &hiding_nonce);
        let statement =
            issue_statement::<P>(&self.inner.context, &credential_context.0, &commitment);
        let proof_result = prove(
            &self.inner.profile.params(),
            &statement,
            &circuit,
            &witness,
            rng,
        );
        let proof = proof_result.map_err(proof_error)?;
        Ok((
            PendingIssue {
                issuer_context: self.inner.context,
                credential_context,
                secret: *secret,
                hiding_nonce: *hiding_nonce,
                commitment: commitment.clone(),
                params: PhantomData,
            },
            IssueRequest {
                commitment,
                proof,
                params: PhantomData,
            },
        ))
    }

    fn verify_credential(&self, credential: &Credential<P>) -> Result<(), Error> {
        if credential.issuer_context != self.inner.context {
            return Err(Error::WrongIssuer);
        }
        let scope = credential_scope(&credential.issuer_context, &credential.credential_context.0);
        let commitment = Zeroizing::new(credential_target::<P>(
            &scope,
            &credential.secret,
            &credential.hiding_nonce,
        ));
        let target = Zeroizing::new(signed_credential_target::<P>(&commitment, &credential.salt));
        let evaluated = Zeroizing::new(
            mayo::eval(&self.inner.mayo, &credential.signature)
                .map_err(|_| Error::InvalidSignature)?,
        );
        if !gf16_slices_equal(&evaluated, &target) {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }

    /// Verify a presentation proof without consuming its deterministic tag.
    ///
    /// Most applications should use [`Verifier::verify`] instead. Proof-only
    /// verification does not enforce the rate limit; a successful tag must
    /// still be inserted atomically into a durable [`TagStore`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPresentationLimit`] for a zero limit or
    /// [`Error::InvalidProof`] when the presentation proof is invalid.
    pub fn verify_proof_only(
        &self,
        challenge: &PresentationChallenge,
        presentation: &Presentation<P>,
    ) -> Result<VerifiedPresentation, Error> {
        if challenge.limit == 0 {
            return Err(Error::InvalidPresentationLimit);
        }
        let credential_scope =
            credential_scope(&self.inner.context, &challenge.credential_context.0);
        let scope = presentation_scope(
            &self.inner.context,
            &challenge.credential_context.0,
            &challenge.presentation_context.0,
        );
        let circuit = PresentationCircuit::<P> {
            mayo_system: &self.inner.mayo_system,
            credential_scope,
            presentation_scope: scope,
            presentation_limit: challenge.limit,
            tag: presentation.tag,
            params: PhantomData,
        };
        let statement =
            presentation_statement::<P>(&self.inner.context, challenge, &presentation.tag);
        verify(
            &self.inner.profile.params(),
            &statement,
            &circuit,
            &presentation.proof,
        )
        .map_err(proof_error)?;
        Ok(VerifiedPresentation {
            scope,
            tag: presentation.tag,
        })
    }
}

/// Issuer holding the MAYO trapdoor used only during credential issuance.
pub struct Issuer<P: ArcParams = Mayo2> {
    secret: MayoSecretKey<P>,
    public: PublicKey<P>,
}

impl<P: ArcParams> Issuer<P> {
    /// Generate an issuer using the balanced VOLE profile.
    pub fn generate(application_context: &[u8], rng: &mut impl CryptoRngCore) -> Self {
        Self::generate_with_profile(application_context, PerformanceProfile::Balanced, rng)
    }

    /// Generate an issuer with an explicit proof-size/latency profile.
    ///
    /// # Panics
    ///
    /// Panics if `application_context` exceeds
    /// [`MAX_APPLICATION_CONTEXT_BYTES`].
    pub fn generate_with_profile(
        application_context: &[u8],
        profile: PerformanceProfile,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        assert!(
            application_context.len() <= MAX_APPLICATION_CONTEXT_BYTES,
            "application context exceeds MAX_APPLICATION_CONTEXT_BYTES"
        );
        let (secret, mayo) = mayo::trapgen::<P>(rng);
        let (mayo_system, public_key_hash) = mayo_system_and_hash(&mayo);
        let context = derive_issuer_context::<P>(application_context, &public_key_hash, profile);
        Self {
            secret,
            public: PublicKey {
                inner: Arc::new(PublicInner {
                    mayo,
                    mayo_system,
                    context,
                    profile,
                    application_context: application_context.to_vec(),
                }),
            },
        }
    }

    /// Borrow the issuer public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey<P> {
        &self.public
    }

    /// Encode the issuer trapdoor and public configuration canonically.
    ///
    /// These bytes contain the issuer secret key and provide no
    /// confidentiality or integrity. Seal them with application-managed key
    /// storage protection before persistence.
    #[must_use]
    pub fn key_bytes(&self) -> Vec<u8> {
        let secret = Zeroizing::new(self.secret.to_bytes());
        let mut output =
            Vec::with_capacity(16 + self.public.inner.application_context.len() + secret.len());
        wire::header(&mut output, WIRE_ISSUER_KEY, P::WIRE_ID);
        output.push(self.public.inner.profile.wire_id());
        wire::put_bytes(&mut output, &self.public.inner.application_context);
        wire::put_bytes(&mut output, &secret);
        output
    }

    /// Restore an issuer from canonical, unprotected key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] when the envelope, suite, profile, application
    /// context, MAYO trapdoor, or trailing data is invalid.
    pub fn from_key_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes, WIRE_ISSUER_KEY, P::WIRE_ID)?;
        let profile = PerformanceProfile::from_wire_id(decoder.u8()?)?;
        let application_context = decoder.bytes()?;
        if application_context.len() > MAX_APPLICATION_CONTEXT_BYTES {
            return Err(WireError::InvalidEncoding);
        }
        let application_context = application_context.to_vec();
        let secret = MayoSecretKey::<P>::from_bytes(decoder.bytes()?)
            .map_err(|_| WireError::InvalidEncoding)?;
        decoder.finish()?;
        let mayo = secret.public_key();
        let (mayo_system, public_key_hash) = mayo_system_and_hash(&mayo);
        let context = derive_issuer_context::<P>(&application_context, &public_key_hash, profile);
        Ok(Self {
            secret,
            public: PublicKey {
                inner: Arc::new(PublicInner {
                    mayo,
                    mayo_system,
                    context,
                    profile,
                    application_context,
                }),
            },
        })
    }

    /// Verify a request for the policy-selected credential context, then
    /// authenticate its commitment using a fresh signer salt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRequest`] for a malformed commitment,
    /// [`Error::InvalidProof`] for an invalid proof, or
    /// [`Error::SigningFailed`] if MAYO preimage sampling fails.
    pub fn issue(
        &self,
        request: &IssueRequest<P>,
        credential_context: CredentialContext,
        rng: &mut impl CryptoRngCore,
    ) -> Result<IssueResponse<P>, Error> {
        if request.commitment.len() != P::M {
            return Err(Error::InvalidRequest);
        }
        let scope = credential_scope(&self.public.inner.context, &credential_context.0);
        let circuit = IssueCircuit::<P> {
            credential_scope: scope,
            target: request.commitment.clone(),
            params: PhantomData,
        };
        let statement = issue_statement::<P>(
            &self.public.inner.context,
            &credential_context.0,
            &request.commitment,
        );
        verify(
            &self.public.inner.profile.params(),
            &statement,
            &circuit,
            &request.proof,
        )
        .map_err(proof_error)?;

        // The signer selects the salt after accepting the proof, so the
        // requester cannot choose the MAYO target.
        let mut salt = Zeroizing::new([0u8; SALT_BYTES]);
        rng.fill_bytes(&mut salt[..]);
        let target = Zeroizing::new(signed_credential_target::<P>(&request.commitment, &salt));
        let signature = mayo::spre(&self.secret, &target, rng).map_err(|_| Error::SigningFailed)?;
        Ok(IssueResponse {
            signature,
            salt: *salt,
            params: PhantomData,
        })
    }
}

/// Client-side secret state retained while an issuance request is in flight.
pub struct PendingIssue<P: ArcParams = Mayo2> {
    issuer_context: [u8; 32],
    credential_context: CredentialContext,
    secret: [u8; 32],
    hiding_nonce: [u8; 32],
    commitment: Vec<GF16>,
    params: PhantomData<P>,
}

impl<P: ArcParams> Drop for PendingIssue<P> {
    fn drop(&mut self) {
        self.issuer_context.zeroize();
        self.credential_context.0.zeroize();
        self.secret.zeroize();
        self.hiding_nonce.zeroize();
        self.commitment.zeroize();
    }
}

impl<P: ArcParams> ZeroizeOnDrop for PendingIssue<P> {}

impl<P: ArcParams> PendingIssue<P> {
    /// Encode unprotected crash-recovery state.
    ///
    /// These bytes contain credential secrets and provide no confidentiality,
    /// integrity, or rollback protection. Seal them with application-managed
    /// storage protection before persistence.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(144);
        wire::header(&mut output, WIRE_PENDING_ISSUE, P::WIRE_ID);
        output.extend_from_slice(&self.issuer_context);
        output.extend_from_slice(&self.credential_context.0);
        output.extend_from_slice(&self.secret);
        output.extend_from_slice(&self.hiding_nonce);
        output
    }

    /// Restore canonical pending issuance state for this public key.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] when the envelope is malformed, belongs to a
    /// different suite or issuer, exceeds a bound, or has trailing data.
    pub fn from_bytes(public: &PublicKey<P>, bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes, WIRE_PENDING_ISSUE, P::WIRE_ID)?;
        let issuer_context = decoder.array()?;
        let credential_context = CredentialContext(decoder.array()?);
        let secret = Zeroizing::new(decoder.array()?);
        let hiding_nonce = Zeroizing::new(decoder.array()?);
        decoder.finish()?;
        if issuer_context != public.inner.context {
            return Err(WireError::WrongIssuer);
        }
        let scope = credential_scope(&issuer_context, &credential_context.0);
        let commitment = credential_target::<P>(&scope, &secret, &hiding_nonce);
        Ok(Self {
            issuer_context,
            credential_context,
            secret: *secret,
            hiding_nonce: *hiding_nonce,
            commitment,
            params: PhantomData,
        })
    }

    /// Authenticate the exact response and construct a stateful credential.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WrongIssuer`] for a different public key,
    /// [`Error::InvalidRequest`] when retained state does not match the
    /// request, or [`Error::InvalidSignature`] when the response is invalid.
    pub fn finish(
        self,
        public: &PublicKey<P>,
        request: &IssueRequest<P>,
        response: &IssueResponse<P>,
    ) -> Result<Credential<P>, Error> {
        if self.issuer_context != public.inner.context {
            return Err(Error::WrongIssuer);
        }
        if request.commitment != self.commitment {
            return Err(Error::InvalidRequest);
        }
        let target = Zeroizing::new(signed_credential_target::<P>(
            &self.commitment,
            &response.salt,
        ));
        let evaluated = Zeroizing::new(
            mayo::eval(&public.inner.mayo, &response.signature)
                .map_err(|_| Error::InvalidSignature)?,
        );
        if !gf16_slices_equal(&evaluated, &target) {
            return Err(Error::InvalidSignature);
        }
        Ok(Credential {
            issuer_context: self.issuer_context,
            credential_context: self.credential_context,
            signature: response.signature.clone(),
            secret: self.secret,
            hiding_nonce: self.hiding_nonce,
            salt: response.salt,
            next_nonces: BTreeMap::new(),
            params: PhantomData,
        })
    }
}

/// Blind credential-issuance request.
#[derive(Clone, Debug)]
pub struct IssueRequest<P: ArcParams = Mayo2> {
    commitment: Vec<GF16>,
    proof: Proof,
    params: PhantomData<P>,
}

impl<P: ArcParams> IssueRequest<P> {
    /// Hidden-secret commitment authenticated after proof verification.
    #[must_use]
    pub fn commitment(&self) -> &[GF16] {
        &self.commitment
    }

    /// Proof that the commitment has a well-formed hidden opening.
    #[must_use]
    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    /// Encode this network request canonically.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let proof = self.proof.to_bytes();
        let mut output = Vec::with_capacity(16 + self.commitment.len().div_ceil(2) + proof.len());
        wire::header(&mut output, WIRE_ISSUE_REQUEST, P::WIRE_ID);
        output.extend_from_slice(&wire::pack_nibbles(&self.commitment));
        wire::put_bytes(&mut output, &proof);
        output
    }

    /// Decode a canonical issuance request.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] when the envelope, suite, commitment, proof, or
    /// trailing data is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes, WIRE_ISSUE_REQUEST, P::WIRE_ID)?;
        let commitment = decoder.nibbles(P::M)?;
        let proof = decode_proof(decoder.bytes()?)?;
        decoder.finish()?;
        Ok(Self {
            commitment,
            proof,
            params: PhantomData,
        })
    }
}

/// Signer-salted issuer response completing credential issuance.
pub struct IssueResponse<P: ArcParams = Mayo2> {
    signature: Vec<GF16>,
    salt: [u8; SALT_BYTES],
    params: PhantomData<P>,
}

impl<P: ArcParams> Clone for IssueResponse<P> {
    fn clone(&self) -> Self {
        Self {
            signature: self.signature.clone(),
            salt: self.salt,
            params: PhantomData,
        }
    }
}

impl<P: ArcParams> core::fmt::Debug for IssueResponse<P> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("IssueResponse")
            .field("parameter_set", &P::NAME)
            .finish_non_exhaustive()
    }
}

impl<P: ArcParams> Drop for IssueResponse<P> {
    fn drop(&mut self) {
        self.signature.zeroize();
        self.salt.zeroize();
    }
}

impl<P: ArcParams> ZeroizeOnDrop for IssueResponse<P> {}

impl<P: ArcParams> IssueResponse<P> {
    /// Encode this network response canonically.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(16 + self.signature.len().div_ceil(2) + SALT_BYTES);
        wire::header(&mut output, WIRE_ISSUE_RESPONSE, P::WIRE_ID);
        let packed_signature = Zeroizing::new(wire::pack_nibbles(&self.signature));
        output.extend_from_slice(&packed_signature);
        output.extend_from_slice(&self.salt);
        output
    }

    /// Decode a canonical issuance response.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] when the envelope, suite, signature, salt, or
    /// trailing data is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes, WIRE_ISSUE_RESPONSE, P::WIRE_ID)?;
        let signature = Zeroizing::new(decoder.nibbles(P::KN)?);
        let salt = Zeroizing::new(decoder.array()?);
        decoder.finish()?;
        Ok(Self {
            signature: signature.to_vec(),
            salt: *salt,
            params: PhantomData,
        })
    }
}

/// Client-held anonymous credential plus a counter for each presentation
/// context it has used.
///
/// The counter map is privacy-critical. Persist the updated credential after
/// [`Credential::present`] succeeds and before transmitting the returned
/// presentation. Rollback can repeat a tag and link the retry to an earlier
/// presentation. A correct server rejects the duplicate, so rollback does not
/// increase the cryptographic limit.
// The field name is protocol terminology and distinguishes it from the issuer
// and presentation contexts stored in or used with a credential.
#[allow(clippy::struct_field_names)]
pub struct Credential<P: ArcParams = Mayo2> {
    issuer_context: [u8; 32],
    credential_context: CredentialContext,
    signature: Vec<GF16>,
    secret: [u8; 32],
    hiding_nonce: [u8; 32],
    salt: [u8; SALT_BYTES],
    next_nonces: BTreeMap<CounterKey, u32>,
    params: PhantomData<P>,
}

impl<P: ArcParams> Drop for Credential<P> {
    fn drop(&mut self) {
        self.issuer_context.zeroize();
        self.credential_context.0.zeroize();
        self.signature.zeroize();
        self.secret.zeroize();
        self.hiding_nonce.zeroize();
        self.salt.zeroize();
        for next_nonce in self.next_nonces.values_mut() {
            next_nonce.zeroize();
        }
    }
}

impl<P: ArcParams> ZeroizeOnDrop for Credential<P> {}

impl<P: ArcParams> Credential<P> {
    /// Public issuance context authenticated by this credential.
    #[must_use]
    pub fn credential_context(&self) -> CredentialContext {
        self.credential_context
    }

    /// Next hidden nonce for a presentation context, or zero if unused.
    #[must_use]
    pub fn next_nonce(&self, context: PresentationContext) -> u32 {
        self.next_nonces.get(&context.0).copied().unwrap_or(0)
    }

    /// Number of scoped counter records retained by this credential.
    #[must_use]
    pub fn context_count(&self) -> usize {
        self.next_nonces.len()
    }

    /// Produce a proof and deterministic tag for one scoped use.
    ///
    /// The local counter is advanced only after proof construction succeeds.
    /// Persist the updated credential before sending the presentation.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] when the issuer or credential context differs,
    /// the limit is invalid or exhausted, the context-state bound is reached,
    /// or the proof backend fails.
    pub fn present(
        &mut self,
        public: &PublicKey<P>,
        challenge: &PresentationChallenge,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Presentation<P>, Error> {
        if self.issuer_context != public.inner.context {
            return Err(Error::WrongIssuer);
        }
        if self.credential_context != challenge.credential_context {
            return Err(Error::WrongCredentialContext);
        }
        if challenge.limit == 0 {
            return Err(Error::InvalidPresentationLimit);
        }
        // Both credential constructors authenticate the MAYO preimage, and
        // the presentation circuit checks it again. A native evaluation here
        // would duplicate work and add a secret-bearing timing surface.

        let context_key = challenge.presentation_context.0;
        let is_new_context = !self.next_nonces.contains_key(&context_key);
        if is_new_context && self.next_nonces.len() >= MAX_PRESENTATION_CONTEXTS {
            return Err(Error::TooManyPresentationContexts);
        }
        let nonce = self.next_nonces.get(&context_key).copied().unwrap_or(0);
        if nonce >= challenge.limit {
            return Err(Error::RateLimitReached);
        }

        let credential_scope = credential_scope(&self.issuer_context, &self.credential_context.0);
        let scope = presentation_scope(
            &self.issuer_context,
            &self.credential_context.0,
            &challenge.presentation_context.0,
        );
        let tag = derive_tag(&self.secret, &scope, nonce);
        let circuit = PresentationCircuit::<P> {
            mayo_system: &public.inner.mayo_system,
            credential_scope,
            presentation_scope: scope,
            presentation_limit: challenge.limit,
            tag,
            params: PhantomData,
        };
        let secrets = PresentationSecrets {
            signature: &self.signature,
            secret: &self.secret,
            hiding_nonce: &self.hiding_nonce,
            salt: &self.salt,
            presentation_nonce: nonce,
        };
        let witness = circuit.witness(&secrets);
        let statement = presentation_statement::<P>(&self.issuer_context, challenge, &tag);
        let proof_result = prove(
            &public.inner.profile.params(),
            &statement,
            &circuit,
            &witness,
            rng,
        );
        let proof = proof_result.map_err(proof_error)?;
        self.next_nonces.insert(CounterKey(context_key), nonce + 1);
        Ok(Presentation {
            tag,
            proof,
            params: PhantomData,
        })
    }

    /// Encode the credential and all scoped counters without storage
    /// protection.
    ///
    /// These bytes contain the credential authenticator, hidden tag key, and
    /// privacy-sensitive state. The MAYO authenticator does not bind the
    /// counter map, so this encoding provides neither counter integrity nor
    /// rollback protection. Seal it with application-managed storage
    /// protection before persistence.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(
            160 + self.signature.len().div_ceil(2) + 36 * self.next_nonces.len(),
        );
        wire::header(&mut output, WIRE_CREDENTIAL, P::WIRE_ID);
        output.extend_from_slice(&self.issuer_context);
        output.extend_from_slice(&self.credential_context.0);
        let packed_signature = Zeroizing::new(wire::pack_nibbles(&self.signature));
        output.extend_from_slice(&packed_signature);
        output.extend_from_slice(&self.secret);
        output.extend_from_slice(&self.hiding_nonce);
        output.extend_from_slice(&self.salt);
        debug_assert!(self.next_nonces.len() <= MAX_PRESENTATION_CONTEXTS);
        // Construction and decoding enforce the much smaller protocol bound.
        // If that invariant is broken internally, encode a value the decoder
        // rejects instead of truncating or panicking in this infallible API.
        let context_count = u32::try_from(self.next_nonces.len()).unwrap_or(u32::MAX);
        output.extend_from_slice(&context_count.to_le_bytes());
        for (context, next_nonce) in &self.next_nonces {
            output.extend_from_slice(&context.0);
            output.extend_from_slice(&next_nonce.to_le_bytes());
        }
        output
    }

    /// Decode and cryptographically authenticate a credential, then restore
    /// its unauthenticated scoped counters.
    ///
    /// This checks the MAYO credential relation. It cannot detect a removed
    /// counter, a lower counter, or an older snapshot. The storage layer must
    /// provide integrity and rollback protection.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] when the envelope or counter map is
    /// noncanonical, the suite or issuer differs, a bound is exceeded, the
    /// MAYO credential relation fails, or trailing data remains.
    pub fn from_bytes(public: &PublicKey<P>, bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes, WIRE_CREDENTIAL, P::WIRE_ID)?;
        let issuer_context = decoder.array()?;
        let credential_context = CredentialContext(decoder.array()?);
        let signature = Zeroizing::new(decoder.nibbles(P::KN)?);
        let secret = Zeroizing::new(decoder.array()?);
        let hiding_nonce = Zeroizing::new(decoder.array()?);
        let salt = Zeroizing::new(decoder.array()?);
        let context_count =
            usize::try_from(decoder.u32()?).map_err(|_| WireError::InvalidEncoding)?;
        if context_count > MAX_PRESENTATION_CONTEXTS {
            return Err(WireError::InvalidEncoding);
        }
        let mut next_nonces = BTreeMap::new();
        let mut previous: Option<[u8; 32]> = None;
        for _ in 0..context_count {
            let context: [u8; 32] = decoder.array()?;
            if previous.is_some_and(|prior| prior >= context) {
                return Err(WireError::InvalidEncoding);
            }
            previous = Some(context);
            let next_nonce = decoder.u32()?;
            if next_nonce == 0 {
                return Err(WireError::InvalidEncoding);
            }
            next_nonces.insert(CounterKey(context), next_nonce);
        }
        decoder.finish()?;
        if issuer_context != public.inner.context {
            return Err(WireError::WrongIssuer);
        }
        let credential = Self {
            issuer_context,
            credential_context,
            signature: signature.to_vec(),
            secret: *secret,
            hiding_nonce: *hiding_nonce,
            salt: *salt,
            next_nonces,
            params: PhantomData,
        };
        public
            .verify_credential(&credential)
            .map_err(|_| WireError::InvalidCredential)?;
        Ok(credential)
    }
}

/// Non-interactive credential presentation.
#[derive(Clone, Debug)]
pub struct Presentation<P: ArcParams = Mayo2> {
    tag: [u8; 32],
    proof: Proof,
    params: PhantomData<P>,
}

impl<P: ArcParams> Presentation<P> {
    /// Deterministic tag consumed by the relying party's scoped store.
    #[must_use]
    pub fn tag(&self) -> [u8; 32] {
        self.tag
    }

    /// Zero-knowledge possession, tag-derivation, and range proof.
    #[must_use]
    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    /// Encode this network presentation canonically.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let proof = self.proof.to_bytes();
        let mut output = Vec::with_capacity(48 + proof.len());
        wire::header(&mut output, WIRE_PRESENTATION, P::WIRE_ID);
        output.extend_from_slice(&self.tag);
        wire::put_bytes(&mut output, &proof);
        output
    }

    /// Decode a canonical presentation.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] when the envelope, suite, proof, or trailing data
    /// is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes, WIRE_PRESENTATION, P::WIRE_ID)?;
        let tag = decoder.array()?;
        let proof = decode_proof(decoder.bytes()?)?;
        decoder.finish()?;
        Ok(Self {
            tag,
            proof,
            params: PhantomData,
        })
    }
}

/// A valid proof and its exact durable storage key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "a verified tag must be consumed atomically to enforce the rate limit"]
pub struct VerifiedPresentation {
    scope: [u8; 32],
    tag: [u8; 32],
}

impl VerifiedPresentation {
    /// Effective scope binding issuer, credential context, and presentation
    /// context.
    #[must_use]
    pub fn storage_scope(self) -> [u8; 32] {
        self.scope
    }

    /// Deterministic tag to insert within [`Self::storage_scope`].
    #[must_use]
    pub fn tag(self) -> [u8; 32] {
        self.tag
    }
}

/// Stateful verifier coupling proof verification to atomic tag consumption.
pub struct Verifier<P: ArcParams = Mayo2, S: TagStore = MemoryTagStore> {
    public: PublicKey<P>,
    store: S,
}

impl<P: ArcParams> Verifier<P, MemoryTagStore> {
    /// Construct a process-local verifier for tests and examples.
    ///
    /// The built-in store is not crash-safe and must not be used for a
    /// production rate limit.
    #[must_use]
    pub fn new(public: PublicKey<P>) -> Self {
        Self {
            public,
            store: MemoryTagStore::default(),
        }
    }

    /// Number of accepted tags in the process-local store.
    #[must_use]
    pub fn accepted_count(&self) -> usize {
        self.store.len()
    }
}

impl<P: ArcParams, S: TagStore> Verifier<P, S> {
    /// Construct a verifier with an application-supplied durable store.
    #[must_use]
    pub fn with_store(public: PublicKey<P>, store: S) -> Self {
        Self { public, store }
    }

    /// Borrow the verifier public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey<P> {
        &self.public
    }

    /// Borrow the tag store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Mutably borrow the tag store.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Verify a presentation and atomically consume its scoped tag.
    ///
    /// The caller may perform the protected action only after this returns
    /// successfully.
    ///
    /// # Errors
    ///
    /// Returns a proof-validation [`Error`], [`Error::TagAlreadyUsed`] for a
    /// duplicate, or the error returned by the configured [`TagStore`].
    pub fn verify(
        &mut self,
        challenge: &PresentationChallenge,
        presentation: &Presentation<P>,
    ) -> Result<VerifiedPresentation, Error> {
        let verified = self.public.verify_proof_only(challenge, presentation)?;
        let inserted = self.store.insert_if_absent(verified.scope, verified.tag)?;
        if !inserted {
            return Err(Error::TagAlreadyUsed);
        }
        Ok(verified)
    }
}

fn derive_issuer_context<P: ArcParams>(
    application_context: &[u8],
    public_key_hash: &[u8; 32],
    profile: PerformanceProfile,
) -> [u8; 32] {
    let mut hash = sha3::Shake256::default();
    hash.update(b"VOLE-ARC/issuer-context/v1");
    hash.update(&(application_context.len() as u64).to_le_bytes());
    hash.update(application_context);
    hash.update(public_key_hash);
    hash.update(P::NAME.as_bytes());
    hash.update(&32u64.to_le_bytes());
    let params = profile.params();
    hash.update(&(params.tau as u64).to_le_bytes());
    hash.update(&(params.k as u64).to_le_bytes());
    let mut output = [0u8; 32];
    hash.finalize_xof().read(&mut output);
    output
}

fn gf16_slices_equal(left: &[GF16], right: &[GF16]) -> bool {
    left.len() == right.len()
        && bool::from(GF16::slice_as_bytes(left).ct_eq(GF16::slice_as_bytes(right)))
}

fn encode_bytes(bytes: &[u8], output: &mut Vec<u8>) {
    output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    output.extend_from_slice(bytes);
}

fn encode_target(target: &[GF16], output: &mut Vec<u8>) {
    output.extend_from_slice(&(target.len() as u64).to_le_bytes());
    output.extend(target.iter().map(|element| element.to_u8()));
}

fn issue_statement<P: ArcParams>(
    issuer_context: &[u8; 32],
    credential_context: &[u8; 32],
    commitment: &[GF16],
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(ISSUE_STATEMENT);
    encode_bytes(P::NAME.as_bytes(), &mut output);
    output.extend_from_slice(issuer_context);
    output.extend_from_slice(credential_context);
    encode_target(commitment, &mut output);
    output
}

fn presentation_statement<P: ArcParams>(
    issuer_context: &[u8; 32],
    challenge: &PresentationChallenge,
    tag: &[u8; 32],
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(PRESENTATION_STATEMENT);
    encode_bytes(P::NAME.as_bytes(), &mut output);
    output.extend_from_slice(issuer_context);
    output.extend_from_slice(&challenge.credential_context.0);
    output.extend_from_slice(&challenge.presentation_context.0);
    output.extend_from_slice(&challenge.limit.to_le_bytes());
    output.extend_from_slice(&challenge.binding.0);
    output.extend_from_slice(tag);
    output
}

fn decode_proof(bytes: &[u8]) -> Result<Proof, WireError> {
    Proof::from_bytes(bytes).map_err(|error| match error {
        voleith::ProofDecodeError::TooLarge => WireError::TooLarge,
        voleith::ProofDecodeError::InvalidEncoding => WireError::InvalidEncoding,
        voleith::ProofDecodeError::UnsupportedVersion => WireError::UnsupportedVersion,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PresentationBinding, PresentationContext};
    use mayo::{Mayo1, MayoParams};
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    struct FailingStore;

    impl TagStore for FailingStore {
        fn insert_if_absent(&mut self, _scope: [u8; 32], _tag: [u8; 32]) -> Result<bool, Error> {
            Err(Error::StorageFailure)
        }
    }

    fn challenge(
        credential_context: CredentialContext,
        presentation_context: PresentationContext,
        limit: u32,
        binding: &[u8],
    ) -> PresentationChallenge {
        PresentationChallenge::new(
            credential_context,
            presentation_context,
            limit,
            PresentationBinding::new(binding),
        )
        .unwrap()
    }

    fn wire_fingerprint(bytes: &[u8]) -> [u8; 32] {
        let mut hash = sha3::Shake256::default();
        hash.update(b"VOLE-ARC/test-vector-fingerprint/v1");
        hash.update(&(bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
        let mut fingerprint = [0u8; 32];
        hash.finalize_xof().read(&mut fingerprint);
        fingerprint
    }

    fn deterministic_wire_fingerprints<P: ArcParams>(seed: u64) -> [[u8; 32]; 5] {
        let mut rng = StdRng::seed_from_u64(seed);
        let issuer = Issuer::<P>::generate_with_profile(
            b"test-vector/issuer-epoch-1",
            PerformanceProfile::Balanced,
            &mut rng,
        );
        let public = issuer.public_key().clone();
        let credential_context = CredentialContext::new(b"test-vector/credential");
        let (pending, request) = public.prepare_issue(credential_context, &mut rng).unwrap();
        let response = issuer
            .issue(&request, credential_context, &mut rng)
            .unwrap();
        let mut credential = pending.finish(&public, &request, &response).unwrap();
        let presentation_context =
            PresentationContext::scoped(b"vector.example", b"write", Some(b"epoch-9"));
        let challenge = challenge(
            credential_context,
            presentation_context,
            7,
            b"test-vector/binding",
        );
        let presentation = credential.present(&public, &challenge, &mut rng).unwrap();

        [
            public.to_bytes(),
            request.to_bytes(),
            response.to_bytes(),
            credential.to_bytes(),
            presentation.to_bytes(),
        ]
        .map(|bytes| wire_fingerprint(&bytes))
    }

    #[test]
    fn deterministic_mayo1_wire_vector() {
        let fingerprints = deterministic_wire_fingerprints::<Mayo1>(0x5641_5243_5645_4354);

        assert_eq!(
            fingerprints,
            [
                [
                    0x59, 0x88, 0x6e, 0x3e, 0x95, 0xb2, 0xee, 0x99, 0x6e, 0x7c, 0x7c, 0x4c, 0xcd,
                    0x43, 0x79, 0x2b, 0xa7, 0x49, 0x4f, 0x69, 0x30, 0x8b, 0xfa, 0x00, 0x04, 0x28,
                    0xe2, 0xba, 0x38, 0xda, 0x2b, 0xea,
                ],
                [
                    0x67, 0x7c, 0x08, 0x29, 0x78, 0xa1, 0x0b, 0xfe, 0xad, 0xd3, 0xd4, 0xa7, 0xe6,
                    0xbd, 0x2b, 0xae, 0x61, 0xb9, 0xe0, 0xd0, 0xf2, 0x7a, 0xad, 0x80, 0x3c, 0x45,
                    0x19, 0xdf, 0xe4, 0xb6, 0x8b, 0x68,
                ],
                [
                    0x6b, 0xf5, 0xef, 0x48, 0x7b, 0xb5, 0xb3, 0x48, 0x98, 0xb3, 0x95, 0xc3, 0x49,
                    0xe9, 0x7d, 0x45, 0xcb, 0x0b, 0x7e, 0x46, 0xb8, 0xb0, 0xab, 0x98, 0x7d, 0x5a,
                    0x3f, 0x83, 0xa0, 0xac, 0x9a, 0x51,
                ],
                [
                    0x17, 0x2a, 0x7c, 0xad, 0xee, 0xab, 0xf9, 0x97, 0x16, 0xe2, 0x00, 0x36, 0x64,
                    0xde, 0x35, 0x00, 0xd8, 0xaf, 0x1b, 0xff, 0x75, 0x18, 0xe4, 0x37, 0xb8, 0xdf,
                    0x62, 0xe3, 0x27, 0xe6, 0x8a, 0x8d,
                ],
                [
                    0x78, 0xb9, 0x2d, 0xd0, 0xdb, 0x8e, 0x48, 0xc1, 0x0d, 0x09, 0xac, 0xc7, 0x72,
                    0xe8, 0x3e, 0x82, 0x44, 0x27, 0x62, 0x05, 0xb0, 0xf1, 0xa0, 0xb8, 0xb8, 0xff,
                    0xf5, 0x28, 0xc6, 0xd2, 0x61, 0x25,
                ],
            ]
        );
    }

    #[test]
    fn deterministic_default_mayo2_wire_vector() {
        let fingerprints = deterministic_wire_fingerprints::<Mayo2>(0x5641_5243_4d41_594f);
        assert_eq!(
            fingerprints,
            [
                [
                    0x20, 0x55, 0x48, 0xeb, 0xb1, 0xc5, 0xef, 0x36, 0xe9, 0xfc, 0xfd, 0xfb, 0xd4,
                    0x59, 0x3e, 0x35, 0xaa, 0x77, 0x7b, 0xea, 0x08, 0x3d, 0x37, 0x46, 0x4e, 0xe9,
                    0x17, 0xed, 0x73, 0xe7, 0x6e, 0x89,
                ],
                [
                    0xe9, 0xe7, 0x40, 0xd1, 0x0c, 0x0f, 0x69, 0x77, 0xff, 0x78, 0xb2, 0x14, 0xff,
                    0x24, 0x36, 0x83, 0x9d, 0x99, 0x74, 0x57, 0xec, 0x5a, 0x71, 0x0c, 0x3b, 0x5b,
                    0xc6, 0xec, 0x18, 0xae, 0x13, 0x03,
                ],
                [
                    0xfc, 0xdd, 0xca, 0xeb, 0xe2, 0xdd, 0x51, 0xa1, 0x3a, 0x23, 0x05, 0xaf, 0xb9,
                    0x9e, 0xb6, 0xe4, 0xfc, 0x1d, 0x45, 0xbb, 0x54, 0xaf, 0xf6, 0x03, 0xca, 0x5b,
                    0x30, 0x34, 0x2e, 0x8a, 0x50, 0x70,
                ],
                [
                    0xac, 0x8f, 0x7e, 0xd4, 0x76, 0x4d, 0x14, 0x6b, 0x21, 0x18, 0x0a, 0xac, 0x7e,
                    0x5c, 0xae, 0x13, 0x65, 0x4e, 0xea, 0x38, 0xa9, 0x9d, 0xb6, 0x13, 0xca, 0xd0,
                    0x05, 0x08, 0x38, 0x2d, 0x62, 0x96,
                ],
                [
                    0x22, 0x9d, 0xf0, 0x8e, 0x51, 0x4a, 0x96, 0xe6, 0xad, 0xa3, 0x7e, 0x4f, 0x8a,
                    0xd7, 0x03, 0x89, 0xdf, 0x2f, 0x9d, 0x6b, 0x80, 0x90, 0xd3, 0x36, 0x28, 0x1d,
                    0x76, 0x7c, 0x69, 0x0f, 0x0d, 0xa1,
                ],
            ]
        );
    }

    #[test]
    fn default_mayo2_round_trips_and_rejects_replay() {
        let mut rng = StdRng::seed_from_u64(0x5641_5243_4445_4641);
        let issuer: Issuer = Issuer::generate(b"default-mayo2", &mut rng);
        let issuer = Issuer::from_key_bytes(&issuer.key_bytes()).unwrap();
        let public: PublicKey = PublicKey::from_bytes(&issuer.public_key().to_bytes()).unwrap();
        let credential_context = CredentialContext::new(b"default-suite");
        let (pending, request) = public.prepare_issue(credential_context, &mut rng).unwrap();
        let pending_bytes = pending.to_bytes();
        let request: IssueRequest = IssueRequest::from_bytes(&request.to_bytes()).unwrap();
        let response = issuer
            .issue(&request, credential_context, &mut rng)
            .unwrap();
        let response: IssueResponse = IssueResponse::from_bytes(&response.to_bytes()).unwrap();
        let pending = PendingIssue::from_bytes(&public, &pending_bytes).unwrap();
        let credential = pending.finish(&public, &request, &response).unwrap();
        let mut credential: Credential =
            Credential::from_bytes(&public, &credential.to_bytes()).unwrap();

        let challenge = challenge(
            credential_context,
            PresentationContext::scoped(b"default.example", b"login", Some(b"epoch-1")),
            1,
            b"request",
        );
        let presentation = credential.present(&public, &challenge, &mut rng).unwrap();
        let presentation: Presentation =
            Presentation::from_bytes(&presentation.to_bytes()).unwrap();
        let mut verifier: Verifier = Verifier::new(public);
        let _ = verifier.verify(&challenge, &presentation).unwrap();
        assert_eq!(
            verifier.verify(&challenge, &presentation).unwrap_err(),
            Error::TagAlreadyUsed
        );
    }

    // Keeping the complete state transition in one test makes policy-binding
    // regressions easier to review than splitting the shared fixture.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn scoped_limits_bind_policy_and_survive_wire_round_trips() {
        let mut rng = StdRng::seed_from_u64(0x5641_5243_0001);
        let issuer = Issuer::<Mayo1>::generate_with_profile(
            b"example.net/vole-arc/key-epoch-7",
            PerformanceProfile::LowLatency,
            &mut rng,
        );
        let public = PublicKey::<Mayo1>::from_bytes(&issuer.public_key().to_bytes()).unwrap();
        assert_eq!(public.context(), issuer.public_key().context());

        let credential_context = CredentialContext::new(b"attestation-class/basic");
        let (pending, request) = public.prepare_issue(credential_context, &mut rng).unwrap();
        let pending_bytes = pending.to_bytes();
        let request = IssueRequest::<Mayo1>::from_bytes(&request.to_bytes()).unwrap();
        let response = issuer
            .issue(&request, credential_context, &mut rng)
            .unwrap();
        let response = IssueResponse::<Mayo1>::from_bytes(&response.to_bytes()).unwrap();
        let pending = PendingIssue::<Mayo1>::from_bytes(&public, &pending_bytes).unwrap();
        let mut credential = pending.finish(&public, &request, &response).unwrap();

        let first_scope =
            PresentationContext::scoped(b"rp.example", b"account-create", Some(b"epoch-42"));
        let first = challenge(credential_context, first_scope, 2, b"request-1");
        let presentation0 = credential.present(&public, &first, &mut rng).unwrap();
        let presentation0 = Presentation::<Mayo1>::from_bytes(&presentation0.to_bytes()).unwrap();
        assert_eq!(credential.next_nonce(first_scope), 1);

        // Binding, context, limit, and tag are all Fiat-Shamir inputs.
        let wrong_binding = challenge(credential_context, first_scope, 2, b"request-other");
        assert_eq!(
            public
                .verify_proof_only(&wrong_binding, &presentation0)
                .unwrap_err(),
            Error::InvalidProof
        );
        let wrong_limit = challenge(credential_context, first_scope, 3, b"request-1");
        assert_eq!(
            public
                .verify_proof_only(&wrong_limit, &presentation0)
                .unwrap_err(),
            Error::InvalidProof
        );
        let other_scope =
            PresentationContext::scoped(b"other.example", b"account-create", Some(b"epoch-42"));
        let wrong_scope = challenge(credential_context, other_scope, 2, b"request-1");
        assert_eq!(
            public
                .verify_proof_only(&wrong_scope, &presentation0)
                .unwrap_err(),
            Error::InvalidProof
        );
        let mut tampered = presentation0.clone();
        tampered.tag[0] ^= 1;
        assert_eq!(
            public.verify_proof_only(&first, &tampered).unwrap_err(),
            Error::InvalidProof
        );

        let mut verifier = Verifier::new(public.clone());
        let _ = verifier.verify(&first, &presentation0).unwrap();
        assert_eq!(verifier.accepted_count(), 1);
        assert_eq!(
            verifier.verify(&first, &presentation0).unwrap_err(),
            Error::TagAlreadyUsed
        );

        let second = challenge(credential_context, first_scope, 2, b"request-2");
        let presentation1 = credential.present(&public, &second, &mut rng).unwrap();
        assert_ne!(presentation0.tag(), presentation1.tag());
        let _ = verifier.verify(&second, &presentation1).unwrap();
        assert_eq!(
            credential.present(&public, &second, &mut rng).unwrap_err(),
            Error::RateLimitReached
        );

        // Raising the policy extends the same nonce/tag namespace. It does
        // not create three additional uses after the earlier limit of two.
        let extended = challenge(credential_context, first_scope, 3, b"request-3");
        let presentation2 = credential.present(&public, &extended, &mut rng).unwrap();
        let _ = verifier.verify(&extended, &presentation2).unwrap();
        assert_eq!(credential.next_nonce(first_scope), 3);
        assert_eq!(
            credential
                .present(&public, &extended, &mut rng)
                .unwrap_err(),
            Error::RateLimitReached
        );

        // A new epoch creates an independent bucket.
        let epoch_scope =
            PresentationContext::scoped(b"rp.example", b"account-create", Some(b"epoch-43"));
        let epoch_challenge = challenge(credential_context, epoch_scope, 1, b"request-4");
        let epoch_presentation = credential
            .present(&public, &epoch_challenge, &mut rng)
            .unwrap();
        assert_ne!(presentation0.tag(), epoch_presentation.tag());

        // Verification must fail closed if durable accounting fails.
        let mut failing = Verifier::with_store(public.clone(), FailingStore);
        assert_eq!(
            failing
                .verify(&epoch_challenge, &epoch_presentation)
                .unwrap_err(),
            Error::StorageFailure
        );
        let _ = verifier
            .verify(&epoch_challenge, &epoch_presentation)
            .unwrap();
        assert_eq!(verifier.accepted_count(), 4);
        assert_eq!(credential.context_count(), 2);

        // Credential serialization retains both counters canonically.
        let restored = Credential::<Mayo1>::from_bytes(&public, &credential.to_bytes()).unwrap();
        assert_eq!(restored.next_nonce(first_scope), 3);
        assert_eq!(restored.next_nonce(epoch_scope), 1);

        // Stored context entries are created only after a successful
        // presentation, so a zero next-nonce has a shorter canonical
        // encoding: omit the entry.
        let mut noncanonical = credential.to_bytes();
        let last_nonce = noncanonical.len() - 4;
        noncanonical[last_nonce..].fill(0);
        assert!(matches!(
            Credential::<Mayo1>::from_bytes(&public, &noncanonical),
            Err(WireError::InvalidEncoding)
        ));

        // The MAYO authenticator does not bind the counter suffix. Removing
        // every counter leaves a canonical, authentic credential but resets
        // the nonce and repeats the public tag. The server still rejects it.
        let mut counters_removed = credential.to_bytes();
        let counter_bytes = 36 * credential.context_count();
        let count_offset = counters_removed.len() - counter_bytes - 4;
        counters_removed[count_offset..count_offset + 4].fill(0);
        counters_removed.truncate(count_offset + 4);
        let mut rolled_back = Credential::<Mayo1>::from_bytes(&public, &counters_removed).unwrap();
        let scope = presentation_scope(
            &rolled_back.issuer_context,
            &rolled_back.credential_context.0,
            &first_scope.0,
        );
        assert_eq!(
            derive_tag(&rolled_back.secret, &scope, 0),
            presentation0.tag()
        );
        let repeated = rolled_back.present(&public, &first, &mut rng).unwrap();
        assert_eq!(repeated.tag(), presentation0.tag());
        assert_eq!(
            verifier.verify(&first, &repeated).unwrap_err(),
            Error::TagAlreadyUsed
        );
    }

    #[test]
    fn signer_salt_randomizes_authenticators_without_minting_new_lineage() {
        let mut rng = StdRng::seed_from_u64(0x5641_5243_0002);
        let issuer = Issuer::<Mayo1>::generate_with_profile(
            b"signer-salt",
            PerformanceProfile::LowLatency,
            &mut rng,
        );
        let public = issuer.public_key().clone();
        let credential_context = CredentialContext::new(b"credential-epoch");
        let (pending, request) = public.prepare_issue(credential_context, &mut rng).unwrap();
        let pending_bytes = pending.to_bytes();

        let first = issuer
            .issue(&request, credential_context, &mut rng)
            .unwrap();
        let second = issuer
            .issue(&request, credential_context, &mut rng)
            .unwrap();
        assert_ne!(first.salt, second.salt);
        assert_ne!(first.signature, second.signature);

        let first_credential = PendingIssue::from_bytes(&public, &pending_bytes)
            .unwrap()
            .finish(&public, &request, &first)
            .unwrap();
        let second_credential = PendingIssue::from_bytes(&public, &pending_bytes)
            .unwrap()
            .finish(&public, &request, &second)
            .unwrap();
        let context = PresentationContext::new(b"same-bucket");
        let first_scope = presentation_scope(
            &first_credential.issuer_context,
            &first_credential.credential_context.0,
            &context.0,
        );
        let second_scope = presentation_scope(
            &second_credential.issuer_context,
            &second_credential.credential_context.0,
            &context.0,
        );
        assert_eq!(
            derive_tag(&first_credential.secret, &first_scope, 0),
            derive_tag(&second_credential.secret, &second_scope, 0),
            "two signer salts over one client opening remain one rate-limit lineage"
        );

        let wrong_context = CredentialContext::new(b"different-credential-epoch");
        let mut failure_rng = StdRng::seed_from_u64(0xBAD5_C0DE);
        let mut untouched_rng = failure_rng.clone();
        assert_eq!(
            issuer
                .issue(&request, wrong_context, &mut failure_rng)
                .unwrap_err(),
            Error::InvalidProof
        );
        assert_eq!(
            failure_rng.next_u64(),
            untouched_rng.next_u64(),
            "an invalid issue request must fail before signer randomness is consumed"
        );
    }

    #[test]
    fn proof_circuit_rejects_nonce_equal_to_limit() {
        let mut rng = StdRng::seed_from_u64(0x5641_5243_0004);
        let issuer = Issuer::<Mayo1>::generate_with_profile(
            b"range-proof",
            PerformanceProfile::LowLatency,
            &mut rng,
        );
        let public = issuer.public_key().clone();
        let credential_context = CredentialContext::new(b"credential-context");
        let (pending, request) = public.prepare_issue(credential_context, &mut rng).unwrap();
        let response = issuer
            .issue(&request, credential_context, &mut rng)
            .unwrap();
        let credential = pending.finish(&public, &request, &response).unwrap();
        let presentation_context = PresentationContext::new(b"range-scope");
        let challenge = challenge(
            credential_context,
            presentation_context,
            1,
            b"range-binding",
        );
        let credential_scope =
            credential_scope(&credential.issuer_context, &credential.credential_context.0);
        let scope = presentation_scope(
            &credential.issuer_context,
            &credential.credential_context.0,
            &presentation_context.0,
        );
        let out_of_range_nonce = 1;
        let tag = derive_tag(&credential.secret, &scope, out_of_range_nonce);
        let circuit = PresentationCircuit::<Mayo1> {
            mayo_system: &public.inner.mayo_system,
            credential_scope,
            presentation_scope: scope,
            presentation_limit: challenge.limit,
            tag,
            params: PhantomData,
        };
        let secrets = PresentationSecrets {
            signature: &credential.signature,
            secret: &credential.secret,
            hiding_nonce: &credential.hiding_nonce,
            salt: &credential.salt,
            presentation_nonce: out_of_range_nonce,
        };
        let mut witness = circuit.witness(&secrets);
        let statement =
            presentation_statement::<Mayo1>(&credential.issuer_context, &challenge, &tag);
        let result = prove(
            &public.inner.profile.params(),
            &statement,
            &circuit,
            &witness,
            &mut rng,
        );
        witness.zeroize();
        assert!(matches!(result, Err(voleith::VoleithError::Unsatisfiable)));
    }

    #[test]
    fn cross_key_and_sampled_wire_mutations_fail_closed() {
        let mut rng = StdRng::seed_from_u64(0x5641_5243_0004);
        let issuer = Issuer::<Mayo1>::generate_with_profile(
            b"mutation-tests",
            PerformanceProfile::Compact,
            &mut rng,
        );
        let public = issuer.public_key().clone();
        let credential_context = CredentialContext::new(b"mutation-credential");
        let (pending, request) = public.prepare_issue(credential_context, &mut rng).unwrap();
        let pending_bytes = pending.to_bytes();
        let response = issuer
            .issue(&request, credential_context, &mut rng)
            .unwrap();
        let mut credential = pending.finish(&public, &request, &response).unwrap();
        let challenge = challenge(
            credential_context,
            PresentationContext::new(b"mutation-scope"),
            1,
            b"mutation-binding",
        );
        let presentation = credential.present(&public, &challenge, &mut rng).unwrap();
        let _ = public.verify_proof_only(&challenge, &presentation).unwrap();

        let other_issuer = Issuer::<Mayo1>::generate_with_profile(
            b"mutation-tests/other-key",
            PerformanceProfile::Compact,
            &mut rng,
        );
        assert!(matches!(
            other_issuer.issue(&request, credential_context, &mut rng),
            Err(Error::InvalidProof)
        ));

        let request_bytes = request.to_bytes();
        for offset in mutation_offsets(request_bytes.len()) {
            let mut mutated = request_bytes.clone();
            mutated[offset] ^= 1 << (offset % 8);
            if let Ok(mutated) = IssueRequest::<Mayo1>::from_bytes(&mutated) {
                assert!(
                    issuer
                        .issue(&mutated, credential_context, &mut rng)
                        .is_err(),
                    "mutated issue request accepted at byte {offset}"
                );
            }
        }

        let response_bytes = response.to_bytes();
        for offset in mutation_offsets(response_bytes.len()) {
            let mut mutated = response_bytes.clone();
            mutated[offset] ^= 1 << (offset % 8);
            if let Ok(mutated) = IssueResponse::<Mayo1>::from_bytes(&mutated) {
                let pending = PendingIssue::<Mayo1>::from_bytes(&public, &pending_bytes).unwrap();
                assert!(
                    pending.finish(&public, &request, &mutated).is_err(),
                    "mutated issue response accepted at byte {offset}"
                );
            }
        }

        let presentation_bytes = presentation.to_bytes();
        for offset in mutation_offsets(presentation_bytes.len()) {
            let mut mutated = presentation_bytes.clone();
            mutated[offset] ^= 1 << (offset % 8);
            if let Ok(mutated) = Presentation::<Mayo1>::from_bytes(&mutated) {
                assert!(
                    public.verify_proof_only(&challenge, &mutated).is_err(),
                    "mutated presentation accepted at byte {offset}"
                );
            }
        }
    }

    fn mutation_offsets(len: usize) -> Vec<usize> {
        let mut offsets = vec![
            0,
            4,
            5,
            6,
            8,
            9,
            24,
            40,
            41,
            44,
            45,
            len / 4,
            len / 2,
            3 * len / 4,
            len - 1,
        ];
        offsets.retain(|offset| *offset < len);
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }

    #[test]
    fn issuer_key_round_trip_preserves_public_context() {
        let mut rng = StdRng::seed_from_u64(0x5641_5243_0003);
        let issuer = Issuer::<Mayo1>::generate(b"key-round-trip", &mut rng);
        let restored = Issuer::<Mayo1>::from_key_bytes(&issuer.key_bytes()).unwrap();
        assert_eq!(
            issuer.public_key().to_bytes(),
            restored.public_key().to_bytes()
        );
    }

    #[test]
    fn issuer_key_rejects_oversized_application_context_before_copying() {
        let mut encoded = Vec::new();
        wire::header(&mut encoded, WIRE_ISSUER_KEY, Mayo1::WIRE_ID);
        encoded.push(PerformanceProfile::Balanced.wire_id());
        wire::put_bytes(&mut encoded, &vec![0u8; MAX_APPLICATION_CONTEXT_BYTES + 1]);
        wire::put_bytes(&mut encoded, &[]);

        assert!(matches!(
            Issuer::<Mayo1>::from_key_bytes(&encoded),
            Err(WireError::InvalidEncoding)
        ));
    }
}
