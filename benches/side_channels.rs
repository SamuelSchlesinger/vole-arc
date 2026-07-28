//! Fixed-vs-fixed timing checks for secret-bearing VOLE-ARC operations.
//!
//! This is a dudect-style diagnostic, not a proof of constant-time behavior.
//! Run it on an otherwise idle machine with default features disabled.
#![allow(missing_docs)]
// Welch statistics require floating-point sample counts and durations.
// Practical benchmark counts and single-operation nanoseconds remain well
// below f64's exact-integer boundary.
#![allow(clippy::cast_precision_loss)]

use binary_fields::GF16;
use mayo::{Mayo1, Mayo2, MayoParams};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{RngCore, SeedableRng};
use std::hint::black_box;
use std::time::Instant;
use vole_arc::{
    Credential, CredentialContext, Issuer, PerformanceProfile, PresentationBinding,
    PresentationChallenge, PresentationContext, PublicKey,
};

const LEAKAGE_SIGNAL_T: f64 = 4.5;
const FAIL_T: f64 = 10.0;

#[derive(Clone, Copy, Default)]
struct OnlineStats {
    count: u64,
    mean: f64,
    m2: f64,
}

impl OnlineStats {
    fn push(&mut self, sample: f64) {
        self.count += 1;
        let delta = sample - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = sample - self.mean;
        self.m2 += delta * delta2;
    }

    fn variance(self) -> f64 {
        self.m2 / (self.count.saturating_sub(1).max(1) as f64)
    }
}

fn welch_t(first: OnlineStats, second: OnlineStats) -> f64 {
    let variance = first.variance() / first.count as f64 + second.variance() / second.count as f64;
    if variance == 0.0 {
        0.0
    } else {
        (first.mean - second.mean) / variance.sqrt()
    }
}

fn sample_count(variable: &str, default: usize) -> usize {
    std::env::var(variable)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|count| *count > 0)
        .unwrap_or(default)
}

fn class_schedule(samples_per_class: usize, rng: &mut StdRng) -> Vec<bool> {
    let mut schedule = vec![false; samples_per_class];
    schedule.extend(std::iter::repeat_n(true, samples_per_class));
    schedule.shuffle(rng);
    schedule
}

fn report(name: &str, classes: [OnlineStats; 2]) -> f64 {
    let t = welch_t(classes[0], classes[1]);
    let marker = if t.abs() >= FAIL_T {
        "FAIL"
    } else if t.abs() >= LEAKAGE_SIGNAL_T {
        "SIGNAL"
    } else {
        "no signal"
    };
    println!(
        "{name}: n={}/class mean0={:.1} ns mean1={:.1} ns t={t:.3} ({marker})",
        classes[0].count, classes[0].mean, classes[1].mean,
    );
    t.abs()
}

fn measure_mayo_signing<P: MayoParams>(samples_per_class: usize, seed: u64) -> f64 {
    let mut setup_rng = StdRng::seed_from_u64(seed);
    let (first_key, _) = mayo::trapgen::<P>(&mut setup_rng);
    let (second_key, _) = mayo::trapgen::<P>(&mut setup_rng);
    let target: Vec<GF16> = (0..P::M)
        .map(|index| {
            let nibble =
                u8::try_from((index * 7 + 3) & 0x0f).expect("the target value is masked to 4 bits");
            GF16::new(nibble)
        })
        .collect();

    for key in [&first_key, &second_key] {
        for _ in 0..16 {
            black_box(
                mayo::spre(key, &target, &mut setup_rng).expect("warm-up MAYO preimage sampling"),
            );
        }
    }

    let schedule = class_schedule(samples_per_class, &mut setup_rng);
    let mut classes = [OnlineStats::default(); 2];
    for class in schedule {
        let mut operation_seed = [0u8; 32];
        setup_rng.fill_bytes(&mut operation_seed);
        let mut operation_rng = StdRng::from_seed(operation_seed);
        let key = if class { &second_key } else { &first_key };

        let start = Instant::now();
        let signature = mayo::spre(black_box(key), black_box(&target), &mut operation_rng)
            .expect("MAYO preimage sampling");
        let elapsed = start.elapsed().as_nanos() as f64;
        black_box(signature);
        classes[usize::from(class)].push(elapsed);
    }

    report(&format!("{}/spre", P::NAME), classes)
}

fn issue_credential(
    issuer: &Issuer<Mayo2>,
    public: &PublicKey<Mayo2>,
    credential_context: CredentialContext,
    rng: &mut StdRng,
) -> Vec<u8> {
    let (pending, request) = public
        .prepare_issue(credential_context, rng)
        .expect("prepare timing credential");
    let response = issuer
        .issue(&request, credential_context, rng)
        .expect("issue timing credential");
    pending
        .finish(public, &request, &response)
        .expect("authenticate timing credential")
        .to_bytes()
}

fn measure_presentations(samples_per_class: usize, seed: u64) -> f64 {
    let mut setup_rng = StdRng::seed_from_u64(seed);
    let issuer = Issuer::<Mayo2>::generate_with_profile(
        b"vole-arc/timing/issuer-epoch-1",
        PerformanceProfile::Balanced,
        &mut setup_rng,
    );
    let public = issuer.public_key().clone();
    let credential_context = CredentialContext::new(b"attestation/timing");
    let credential_bytes = [
        issue_credential(&issuer, &public, credential_context, &mut setup_rng),
        issue_credential(&issuer, &public, credential_context, &mut setup_rng),
    ];
    let challenge = PresentationChallenge::new(
        credential_context,
        PresentationContext::scoped(b"timing.example", b"account-create", Some(b"epoch-1")),
        1,
        PresentationBinding::new(b"fixed timing challenge"),
    )
    .expect("nonzero presentation limit");

    for bytes in &credential_bytes {
        for _ in 0..2 {
            let mut credential =
                Credential::<Mayo2>::from_bytes(&public, bytes).expect("restore timing credential");
            black_box(
                credential
                    .present(&public, &challenge, &mut setup_rng)
                    .expect("warm-up presentation"),
            );
        }
    }

    let schedule = class_schedule(samples_per_class, &mut setup_rng);
    let mut classes = [OnlineStats::default(); 2];
    for class in schedule {
        let index = usize::from(class);
        let mut credential = Credential::<Mayo2>::from_bytes(&public, &credential_bytes[index])
            .expect("restore timing credential");
        let mut operation_seed = [0u8; 32];
        setup_rng.fill_bytes(&mut operation_seed);
        let mut operation_rng = StdRng::from_seed(operation_seed);

        let start = Instant::now();
        let presentation = credential
            .present(
                black_box(&public),
                black_box(&challenge),
                &mut operation_rng,
            )
            .expect("produce timing presentation");
        let elapsed = start.elapsed().as_nanos() as f64;
        black_box(presentation);
        classes[index].push(elapsed);
    }

    report("MAYO2/presentation-prove", classes)
}

fn main() {
    let signing_samples = sample_count("VOLE_ARC_CT_SIGNING_SAMPLES", 2_000);
    let presentation_samples = sample_count("VOLE_ARC_CT_PRESENTATION_SAMPLES", 128);
    println!(
        "fixed-vs-fixed timing diagnostic; signing={signing_samples}/class presentation={presentation_samples}/class"
    );

    let maximum_t = [
        measure_mayo_signing::<Mayo1>(signing_samples, 0xD1_0000),
        measure_mayo_signing::<Mayo2>(signing_samples, 0xD2_0000),
        measure_presentations(presentation_samples, 0xD3_0000),
    ]
    .into_iter()
    .fold(0.0_f64, f64::max);

    println!(
        "Interpret |t| >= {LEAKAGE_SIGNAL_T} as a signal requiring investigation. \
         This harness fails at |t| >= {FAIL_T} to reduce noisy-run false positives."
    );
    assert!(
        maximum_t < FAIL_T,
        "strong timing-class separation detected (max |t|={maximum_t:.3})"
    );
}
