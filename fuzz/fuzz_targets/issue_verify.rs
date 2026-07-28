#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::OnceLock;
use support::mutate_valid;
use vole_arc::{
    CredentialContext, IssueRequest, IssueResponse, Issuer, Mayo2, PendingIssue,
    PerformanceProfile, PublicKey,
};

struct Fixture {
    issuer: Issuer<Mayo2>,
    public: PublicKey<Mayo2>,
    credential_context: CredentialContext,
    pending: Vec<u8>,
    request: IssueRequest<Mayo2>,
    request_bytes: Vec<u8>,
    response: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(0x4655_5a5a_4953_5355);
        let issuer = Issuer::<Mayo2>::generate_with_profile(
            b"vole-arc/fuzz/issue/issuer-epoch-1",
            PerformanceProfile::Compact,
            &mut rng,
        );
        let public = issuer.public_key().clone();
        let credential_context = CredentialContext::new(b"fuzz/issue/attestation");
        let (pending, request) = public
            .prepare_issue(credential_context, &mut rng)
            .expect("prepare deterministic issuance fixture");
        let response = issuer
            .issue(&request, credential_context, &mut rng)
            .expect("produce deterministic issuance response");
        Fixture {
            issuer,
            public,
            credential_context,
            pending: pending.to_bytes(),
            request_bytes: request.to_bytes(),
            request,
            response: response.to_bytes(),
        }
    })
}

fn rng_from_input(input: &[u8]) -> StdRng {
    let mut seed = [0u8; 32];
    for (index, value) in input.iter().enumerate() {
        let destination = index % seed.len();
        let rotation = u32::try_from(index % 8).expect("a value below 8 fits in u32");
        seed[destination] = seed[destination].wrapping_add(*value).rotate_left(rotation);
    }
    StdRng::from_seed(seed)
}

fuzz_target!(|input: &[u8]| {
    let fixture = fixture();
    let selector = input.first().copied().unwrap_or(0);
    let mutation = input.get(1..).unwrap_or_default();
    if selector.is_multiple_of(2) {
        let bytes = mutate_valid(&fixture.request_bytes, mutation);
        let Ok(request) = IssueRequest::<Mayo2>::from_bytes(&bytes) else {
            return;
        };
        let mut rng = rng_from_input(input);
        let _ = fixture
            .issuer
            .issue(&request, fixture.credential_context, &mut rng);
    } else {
        let bytes = mutate_valid(&fixture.response, mutation);
        let Ok(response) = IssueResponse::<Mayo2>::from_bytes(&bytes) else {
            return;
        };
        let pending = PendingIssue::<Mayo2>::from_bytes(&fixture.public, &fixture.pending)
            .expect("restore deterministic pending fixture");
        let _ = pending.finish(&fixture.public, &fixture.request, &response);
    }
});
