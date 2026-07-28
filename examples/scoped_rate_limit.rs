//! Minimal scoped-rate-limit flow using process-local state.

use rand::rngs::OsRng;
use vole_arc::{
    CredentialContext, Issuer, Mayo2, PresentationBinding, PresentationChallenge,
    PresentationContext, Verifier,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let issuer = Issuer::<Mayo2>::generate(b"issuer.example/key-epoch-7", &mut rng);
    let public = issuer.public_key().clone();

    let credential_context = CredentialContext::new(b"attestation/basic");
    let (pending, request) = public.prepare_issue(credential_context, &mut rng)?;
    let response = issuer.issue(&request, credential_context, &mut rng)?;
    let mut credential = pending.finish(&public, &request, &response)?;

    let presentation_context =
        PresentationContext::scoped(b"rp.example", b"account-create", Some(b"epoch-42"));
    let challenge = PresentationChallenge::new(
        credential_context,
        presentation_context,
        2,
        PresentationBinding::new(b"canonical request or challenge bytes"),
    )?;
    let presentation = credential.present(&public, &challenge, &mut rng)?;

    // Persist `credential.to_bytes()` before transmitting `presentation`.
    // Replace this process-local verifier with a durable shared TagStore.
    let mut verifier = Verifier::new(public);
    let accepted = verifier.verify(&challenge, &presentation)?;
    assert_eq!(accepted.tag(), presentation.tag());
    Ok(())
}
