#![forbid(unsafe_code)]

//! Scoped anonymous rate-limited credentials.
//!
//! `vole-arc` is a research prototype inspired by the Privacy Pass ARC
//! drafts. A credential can produce at most `limit` unlinkable presentations
//! for each public [`PresentationContext`]. The context can identify a relying
//! party, action, and epoch without requiring a new credential.
//!
//! VOLE-ARC uses VOLE-ACT's experimental MAYO and VOLE-in-the-head stack in
//! place of ARC(P-256)'s keyed credential and Schnorr proofs. Its wire format
//! is incompatible with the Privacy Pass ARC token type. No complete
//! reduction or independent audit exists. Do not use it to protect production
//! traffic or value.

mod circuit;
mod context;
mod keccak;
mod markers;
mod protocol;
mod store;
mod wire;

pub use context::{
    CredentialContext, PresentationBinding, PresentationChallenge, PresentationContext,
};
pub use markers::{ArcParams, Error, PerformanceProfile};
pub use mayo::{Mayo1, Mayo2};
pub use protocol::{
    Credential, IssueRequest, IssueResponse, Issuer, MAX_APPLICATION_CONTEXT_BYTES,
    MAX_PRESENTATION_CONTEXTS, PendingIssue, Presentation, PublicKey, VerifiedPresentation,
    Verifier,
};
pub use store::{MemoryTagStore, TagStore};
pub use wire::{MAX_WIRE_BYTES, WireError};
