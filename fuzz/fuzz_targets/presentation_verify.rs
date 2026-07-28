#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::OnceLock;
use support::mutate_valid;
use vole_arc::{
    CredentialContext, Issuer, Mayo2, PerformanceProfile, Presentation, PresentationBinding,
    PresentationChallenge, PresentationContext, PublicKey,
};

struct Fixture {
    public: PublicKey<Mayo2>,
    challenge: PresentationChallenge,
    presentation: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(0x4655_5a5a_5641_5243);
        let issuer = Issuer::<Mayo2>::generate_with_profile(
            b"vole-arc/fuzz/issuer-epoch-1",
            PerformanceProfile::Compact,
            &mut rng,
        );
        let public = issuer.public_key().clone();
        let credential_context = CredentialContext::new(b"fuzz/attestation");
        let (pending, request) = public
            .prepare_issue(credential_context, &mut rng)
            .expect("prepare deterministic fuzz credential");
        let response = issuer
            .issue(&request, credential_context, &mut rng)
            .expect("issue deterministic fuzz credential");
        let mut credential = pending
            .finish(&public, &request, &response)
            .expect("authenticate deterministic fuzz credential");
        let challenge = PresentationChallenge::new(
            credential_context,
            PresentationContext::scoped(b"fuzz.example", b"account-create", Some(b"epoch-1")),
            1,
            PresentationBinding::new(b"fuzz request binding"),
        )
        .expect("nonzero presentation limit");
        let presentation = credential
            .present(&public, &challenge, &mut rng)
            .expect("produce deterministic fuzz presentation")
            .to_bytes();
        Fixture {
            public,
            challenge,
            presentation,
        }
    })
}

fuzz_target!(|input: &[u8]| {
    let fixture = fixture();
    let bytes = mutate_valid(&fixture.presentation, input);
    if let Ok(presentation) = Presentation::<Mayo2>::from_bytes(&bytes) {
        let _ = fixture
            .public
            .verify_proof_only(&fixture.challenge, &presentation);
    }
});
