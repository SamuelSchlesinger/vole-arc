//! Criterion benchmarks for the complete VOLE-ARC protocol.
#![allow(missing_docs)]

use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, SamplingMode, Throughput, black_box, criterion_group,
    criterion_main, measurement::WallTime,
};
use mayo::{Mayo1, Mayo2};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::Duration;
use vole_arc::{
    ArcParams, Credential, CredentialContext, Error, IssueRequest, IssueResponse, Issuer,
    PerformanceProfile, Presentation, PresentationBinding, PresentationChallenge,
    PresentationContext, PublicKey, TagStore, Verifier,
};

/// A benchmark-only store that exercises the verifier/store call boundary
/// without retaining tags or turning later iterations into replay failures.
#[derive(Default)]
struct AcceptingBenchmarkStore;

impl TagStore for AcceptingBenchmarkStore {
    fn insert_if_absent(&mut self, _scope: [u8; 32], _tag: [u8; 32]) -> Result<bool, Error> {
        Ok(true)
    }
}

struct Fixture<P: ArcParams> {
    issuer: Issuer<P>,
    public: PublicKey<P>,
    credential_context: CredentialContext,
    issue_request: IssueRequest<P>,
    issue_response: IssueResponse<P>,
    credential: Credential<P>,
    challenge: PresentationChallenge,
    presentation: Presentation<P>,
}

impl<P: ArcParams> Fixture<P> {
    fn new(profile: PerformanceProfile, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let issuer = Issuer::<P>::generate_with_profile(
            b"vole-arc/criterion/issuer-epoch-1",
            profile,
            &mut rng,
        );
        let public = issuer.public_key().clone();
        let credential_context = CredentialContext::new(b"attestation/benchmark");
        let (pending, issue_request) = public
            .prepare_issue(credential_context, &mut rng)
            .expect("prepare benchmark issuance");
        let issue_response = issuer
            .issue(&issue_request, credential_context, &mut rng)
            .expect("complete benchmark issuance");
        let mut credential = pending
            .finish(&public, &issue_request, &issue_response)
            .expect("authenticate benchmark credential");
        let challenge = PresentationChallenge::new(
            credential_context,
            PresentationContext::scoped(b"benchmark.example", b"account-create", Some(b"epoch-1")),
            u32::MAX,
            PresentationBinding::new(b"benchmark request binding"),
        )
        .expect("nonzero presentation limit");
        let presentation = credential
            .present(&public, &challenge, &mut rng)
            .expect("prepare benchmark presentation");

        Self {
            issuer,
            public,
            credential_context,
            issue_request,
            issue_response,
            credential,
            challenge,
            presentation,
        }
    }
}

fn profile_name(profile: PerformanceProfile) -> &'static str {
    match profile {
        PerformanceProfile::Compact => "compact",
        PerformanceProfile::Balanced => "balanced",
        PerformanceProfile::LowLatency => "low-latency",
    }
}

// This function keeps every operation for one parameter set beside the shared
// fixture, making omissions and differences between MAYO1 and MAYO2 visible.
#[allow(clippy::too_many_lines)]
fn balanced_parameter_set<P: ArcParams + 'static>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    parameter_set: &'static str,
    seed: u64,
) {
    let mut fixture = Fixture::<P>::new(PerformanceProfile::Balanced, seed);

    let mut key_rng = StdRng::seed_from_u64(seed ^ 0x1000);
    group.bench_with_input(
        BenchmarkId::new("issuer-keygen", parameter_set),
        &parameter_set,
        |b, _| {
            b.iter(|| {
                black_box(Issuer::<P>::generate_with_profile(
                    black_box(b"vole-arc/criterion/keygen"),
                    PerformanceProfile::Balanced,
                    &mut key_rng,
                ))
            });
        },
    );

    let mut issue_client_rng = StdRng::seed_from_u64(seed ^ 0x2000);
    group.bench_with_input(
        BenchmarkId::new("issue/client-prove", parameter_set),
        &parameter_set,
        |b, _| {
            b.iter(|| {
                black_box(
                    fixture
                        .public
                        .prepare_issue(fixture.credential_context, &mut issue_client_rng)
                        .expect("prepare issuance"),
                )
            });
        },
    );

    let mut issue_server_rng = StdRng::seed_from_u64(seed ^ 0x3000);
    group.bench_with_input(
        BenchmarkId::new("issue/issuer-verify-and-sign", parameter_set),
        &parameter_set,
        |b, _| {
            b.iter(|| {
                black_box(
                    fixture
                        .issuer
                        .issue(
                            black_box(&fixture.issue_request),
                            fixture.credential_context,
                            &mut issue_server_rng,
                        )
                        .expect("verify and sign issuance"),
                )
            });
        },
    );

    let mut present_rng = StdRng::seed_from_u64(seed ^ 0x4000);
    group.bench_with_input(
        BenchmarkId::new("presentation/client-prove", parameter_set),
        &parameter_set,
        |b, _| {
            b.iter(|| {
                black_box(
                    fixture
                        .credential
                        .present(&fixture.public, &fixture.challenge, &mut present_rng)
                        .expect("produce presentation"),
                )
            });
        },
    );

    group.bench_with_input(
        BenchmarkId::new("presentation/verifier-proof-only", parameter_set),
        &parameter_set,
        |b, _| {
            b.iter(|| {
                black_box(
                    fixture
                        .public
                        .verify_proof_only(
                            black_box(&fixture.challenge),
                            black_box(&fixture.presentation),
                        )
                        .expect("verify presentation proof"),
                )
            });
        },
    );

    let mut verifier = Verifier::with_store(fixture.public.clone(), AcceptingBenchmarkStore);
    group.bench_with_input(
        BenchmarkId::new("presentation/verifier-and-store", parameter_set),
        &parameter_set,
        |b, _| {
            b.iter(|| {
                black_box(
                    verifier
                        .verify(
                            black_box(&fixture.challenge),
                            black_box(&fixture.presentation),
                        )
                        .expect("verify and consume presentation"),
                )
            });
        },
    );

    let mut presentation_e2e_rng = StdRng::seed_from_u64(seed ^ 0x4800);
    let mut presentation_e2e_verifier =
        Verifier::with_store(fixture.public.clone(), AcceptingBenchmarkStore);
    group.bench_with_input(
        BenchmarkId::new("presentation/end-to-end", parameter_set),
        &parameter_set,
        |b, _| {
            b.iter(|| {
                let presentation = fixture
                    .credential
                    .present(
                        &fixture.public,
                        &fixture.challenge,
                        &mut presentation_e2e_rng,
                    )
                    .expect("produce presentation");
                black_box(
                    presentation_e2e_verifier
                        .verify(&fixture.challenge, &presentation)
                        .expect("verify and consume presentation"),
                )
            });
        },
    );

    let mut issue_e2e_rng = StdRng::seed_from_u64(seed ^ 0x5000);
    group.bench_with_input(
        BenchmarkId::new("issue/end-to-end", parameter_set),
        &parameter_set,
        |b, _| {
            b.iter(|| {
                let (pending, request) = fixture
                    .public
                    .prepare_issue(fixture.credential_context, &mut issue_e2e_rng)
                    .expect("prepare issuance");
                let response = fixture
                    .issuer
                    .issue(&request, fixture.credential_context, &mut issue_e2e_rng)
                    .expect("issue credential");
                black_box(
                    pending
                        .finish(&fixture.public, &request, &response)
                        .expect("authenticate credential"),
                )
            });
        },
    );

    let _ = black_box(&fixture.issue_response);
}

fn balanced_protocol(c: &mut Criterion) {
    let mut group = c.benchmark_group("balanced");
    group.sampling_mode(SamplingMode::Flat);
    balanced_parameter_set::<Mayo2>(&mut group, "MAYO2", 0xA2_0000);
    balanced_parameter_set::<Mayo1>(&mut group, "MAYO1", 0xA1_0000);
    group.finish();
}

fn profile_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("profiles/MAYO2");
    group.sampling_mode(SamplingMode::Flat);

    for (index, profile) in [
        PerformanceProfile::Compact,
        PerformanceProfile::Balanced,
        PerformanceProfile::LowLatency,
    ]
    .into_iter()
    .enumerate()
    {
        let label = profile_name(profile);
        let mut fixture = Fixture::<Mayo2>::new(profile, 0xB0_0000 + index as u64);
        let mut rng = StdRng::seed_from_u64(0xB1_0000 + index as u64);
        eprintln!(
            "MAYO2 {label} wire bytes: issue_request={} presentation={}",
            fixture.issue_request.to_bytes().len(),
            fixture.presentation.to_bytes().len(),
        );

        group.bench_with_input(
            BenchmarkId::new("issue/client-prove", label),
            &profile,
            |b, _| {
                b.iter(|| {
                    black_box(
                        fixture
                            .public
                            .prepare_issue(fixture.credential_context, &mut rng)
                            .expect("prepare issuance"),
                    )
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("presentation/client-prove", label),
            &profile,
            |b, _| {
                b.iter(|| {
                    black_box(
                        fixture
                            .credential
                            .present(&fixture.public, &fixture.challenge, &mut rng)
                            .expect("produce presentation"),
                    )
                });
            },
        );
    }
    group.finish();
}

fn wire_codecs(c: &mut Criterion) {
    let fixture = Fixture::<Mayo2>::new(PerformanceProfile::Balanced, 0xC0_0000);
    let public_bytes = fixture.public.to_bytes();
    let request_bytes = fixture.issue_request.to_bytes();
    let response_bytes = fixture.issue_response.to_bytes();
    let credential_bytes = fixture.credential.to_bytes();
    let presentation_bytes = fixture.presentation.to_bytes();

    eprintln!(
        "balanced MAYO2 wire bytes: public={} issue_request={} issue_response={} credential={} presentation={}",
        public_bytes.len(),
        request_bytes.len(),
        response_bytes.len(),
        credential_bytes.len(),
        presentation_bytes.len(),
    );

    let mut group = c.benchmark_group("wire/balanced-MAYO2");
    group.sampling_mode(SamplingMode::Flat);

    group.throughput(Throughput::Bytes(request_bytes.len() as u64));
    group.bench_function("issue-request/encode", |b| {
        b.iter(|| black_box(fixture.issue_request.to_bytes()));
    });
    group.bench_function("issue-request/decode", |b| {
        b.iter(|| {
            black_box(
                IssueRequest::<Mayo2>::from_bytes(black_box(&request_bytes))
                    .expect("decode issue request"),
            )
        });
    });

    group.throughput(Throughput::Bytes(response_bytes.len() as u64));
    group.bench_function("issue-response/decode", |b| {
        b.iter(|| {
            black_box(
                IssueResponse::<Mayo2>::from_bytes(black_box(&response_bytes))
                    .expect("decode issue response"),
            )
        });
    });

    group.throughput(Throughput::Bytes(presentation_bytes.len() as u64));
    group.bench_function("presentation/encode", |b| {
        b.iter(|| black_box(fixture.presentation.to_bytes()));
    });
    group.bench_function("presentation/decode", |b| {
        b.iter(|| {
            black_box(
                Presentation::<Mayo2>::from_bytes(black_box(&presentation_bytes))
                    .expect("decode presentation"),
            )
        });
    });

    group.throughput(Throughput::Bytes(credential_bytes.len() as u64));
    group.bench_function("credential/decode-and-authenticate", |b| {
        b.iter(|| {
            black_box(
                Credential::<Mayo2>::from_bytes(&fixture.public, black_box(&credential_bytes))
                    .expect("decode credential"),
            )
        });
    });

    group.throughput(Throughput::Bytes(public_bytes.len() as u64));
    group.bench_function("public-key/decode-and-derive", |b| {
        b.iter(|| {
            black_box(
                PublicKey::<Mayo2>::from_bytes(black_box(&public_bytes))
                    .expect("decode public key"),
            )
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = balanced_protocol, profile_comparison, wire_codecs
}
criterion_main!(benches);
