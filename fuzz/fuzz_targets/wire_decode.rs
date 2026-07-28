#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::OnceLock;
use support::mutate_valid;
use vole_arc::{
    ArcParams, Credential, CredentialContext, IssueRequest, IssueResponse, Issuer, Mayo1, Mayo2,
    PendingIssue, PerformanceProfile, Presentation, PresentationBinding, PresentationChallenge,
    PresentationContext, PublicKey,
};

struct WireFixture<P: ArcParams> {
    public: PublicKey<P>,
    issuer_key: Vec<u8>,
    public_key: Vec<u8>,
    pending: Vec<u8>,
    request: Vec<u8>,
    response: Vec<u8>,
    credential: Vec<u8>,
    presentation: Vec<u8>,
}

impl<P: ArcParams> WireFixture<P> {
    fn new(seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let issuer = Issuer::<P>::generate_with_profile(
            b"vole-arc/fuzz/wire/issuer-epoch-1",
            PerformanceProfile::LowLatency,
            &mut rng,
        );
        let public = issuer.public_key().clone();
        let credential_context = CredentialContext::new(b"fuzz/wire/attestation");
        let (pending, request) = public
            .prepare_issue(credential_context, &mut rng)
            .expect("prepare deterministic wire fixture");
        let pending_bytes = pending.to_bytes();
        let response = issuer
            .issue(&request, credential_context, &mut rng)
            .expect("issue deterministic wire fixture");
        let mut credential = pending
            .finish(&public, &request, &response)
            .expect("authenticate deterministic wire fixture");
        let challenge = PresentationChallenge::new(
            credential_context,
            PresentationContext::scoped(b"fuzz.example", b"wire", Some(b"epoch-1")),
            2,
            PresentationBinding::new(b"wire fixture binding"),
        )
        .expect("nonzero presentation limit");
        let presentation = credential
            .present(&public, &challenge, &mut rng)
            .expect("produce deterministic wire fixture");

        Self {
            public,
            issuer_key: issuer.key_bytes(),
            public_key: issuer.public_key().to_bytes(),
            pending: pending_bytes,
            request: request.to_bytes(),
            response: response.to_bytes(),
            credential: credential.to_bytes(),
            presentation: presentation.to_bytes(),
        }
    }
}

struct Fixtures {
    mayo1: WireFixture<Mayo1>,
    mayo2: WireFixture<Mayo2>,
}

fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| Fixtures {
        mayo1: WireFixture::new(0x4655_5a5a_4d41_5931),
        mayo2: WireFixture::new(0x4655_5a5a_4d41_5932),
    })
}

fn exercise<P: ArcParams>(fixture: &WireFixture<P>, artifact: usize, input: &[u8]) {
    let base = match artifact {
        0 => &fixture.issuer_key,
        1 => &fixture.public_key,
        2 => &fixture.pending,
        3 => &fixture.request,
        4 => &fixture.response,
        5 => &fixture.credential,
        _ => &fixture.presentation,
    };
    let bytes = mutate_valid(base, input);
    match artifact {
        0 => {
            let _ = Issuer::<P>::from_key_bytes(&bytes);
        }
        1 => {
            let _ = PublicKey::<P>::from_bytes(&bytes);
        }
        2 => {
            let _ = PendingIssue::<P>::from_bytes(&fixture.public, &bytes);
        }
        3 => {
            let _ = IssueRequest::<P>::from_bytes(&bytes);
        }
        4 => {
            let _ = IssueResponse::<P>::from_bytes(&bytes);
        }
        5 => {
            let _ = Credential::<P>::from_bytes(&fixture.public, &bytes);
        }
        _ => {
            let _ = Presentation::<P>::from_bytes(&bytes);
        }
    }
}

fn exercise_raw<P: ArcParams>(fixture: &WireFixture<P>, bytes: &[u8]) {
    let _ = Issuer::<P>::from_key_bytes(bytes);
    let _ = PublicKey::<P>::from_bytes(bytes);
    let _ = PendingIssue::<P>::from_bytes(&fixture.public, bytes);
    let _ = IssueRequest::<P>::from_bytes(bytes);
    let _ = IssueResponse::<P>::from_bytes(bytes);
    let _ = Credential::<P>::from_bytes(&fixture.public, bytes);
    let _ = Presentation::<P>::from_bytes(bytes);
}

fuzz_target!(|input: &[u8]| {
    let selector = usize::from(input.first().copied().unwrap_or(0));
    let artifact = selector % 7;
    let mutation = input.get(1..).unwrap_or_default();
    let fixtures = fixtures();
    exercise_raw(&fixtures.mayo1, input);
    exercise_raw(&fixtures.mayo2, input);
    if (selector / 7).is_multiple_of(2) {
        exercise(&fixtures.mayo1, artifact, mutation);
    } else {
        exercise(&fixtures.mayo2, artifact, mutation);
    }
});
