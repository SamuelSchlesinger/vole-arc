# VOLE-ARC

> [!WARNING]
> VOLE-ARC is unaudited, experimental cryptographic research. It has no
> production security guarantee and may contain protocol, implementation,
> side-channel, or state-management flaws. Do not use it to protect production
> traffic, accounts, money, or scarce resources. Use it at your own risk.

VOLE-ARC implements scoped anonymous rate-limited credentials. One credential
supports a bounded number of unlinkable presentations in each relying-party,
purpose, or epoch context. The construction uses signer-salted MAYO
authentication, VOLE-in-the-head proofs, context-scoped tags, and a hidden
32-bit counter.

The rate-limit model comes from the Privacy Pass working group's
[ARC cryptography draft][arc-crypto] and [ARC protocol draft][arc-protocol].
VOLE-ARC does not implement ARC(P-256) and is not wire-compatible with token
type `0xE5AC`. It uses an experimental, publicly verifiable MAYO/VOLE
construction and keeps the presentation nonce hidden.

This is unaudited research cryptography. The protocol lacks complete
reductions, an independent implementation, a cryptographic audit, and a
compiler or physical side-channel review. Do not use it to protect production
traffic, accounts, money, or scarce resources.

MAYO2 is the default parameter set, matching VOLE-ACT's category-1 choice.
MAYO1 remains available as a slower category-1 option with a wider
credential-hash output and stronger generic collision margin. These are the
only supported suites: the complete proof layer has 128-bit soundness
parameters and 128-bit tree seeds, so exposing MAYO's category-3 or category-5
types would overstate the security of the combined construction.

## Scoped rate limiting

Four public values define the presentation policy:

| Value | Stable across | Purpose |
|---|---|---|
| `CredentialContext` | credential lifetime | Binds issuance to an attestation class or credential epoch |
| `PresentationContext` | one rate-limit bucket | Identifies relying party, operation, and optional epoch |
| `PresentationBinding` | one request | Binds a challenge or request digest without resetting the bucket |
| `limit` | server policy | Proves the hidden nonce is in `[0, limit)` |

For credential secret `k`, effective scope `S`, and hidden nonce `i`, the
presentation tag is

```text
tag = SHAKE256("VOLE-ARC/tag/v1" || k || S || le32(i), 32).
```

The proof binds `k` to a valid credential, verifies the tag computation, and
proves `i < limit`. A durable store accepts each `(S, tag)` once. Because the
range contains `limit` nonce values, one credential can yield at most
`limit` accepted tags in that scope.

The limit is not hashed into `S` or the tag. Raising a bucket from 5 to 10
therefore permits at most 10 total uses, not 5 old uses plus 10 new ones.
Changing the relying party, purpose, or epoch does create an independent
bucket.

## Example

```rust
use rand::rngs::OsRng;
use vole_arc::{
    CredentialContext, Issuer, Mayo2, PresentationBinding, PresentationChallenge,
    PresentationContext, Verifier,
};

let mut rng = OsRng;
let issuer = Issuer::<Mayo2>::generate(b"issuer.example/key-epoch-7", &mut rng);
let public = issuer.public_key().clone();

// Issuance policy can bind an attestation class or credential epoch.
let credential_context = CredentialContext::new(b"attestation/basic");
let (pending, request) = public.prepare_issue(credential_context, &mut rng)?;
let response = issuer.issue(&request, credential_context, &mut rng)?;
let mut credential = pending.finish(&public, &request, &response)?;

// This bucket allows two account-creation attempts at rp.example in epoch 42.
let context = PresentationContext::scoped(
    b"rp.example",
    b"account-create",
    Some(b"epoch-42"),
);
let challenge = PresentationChallenge::new(
    credential_context,
    context,
    2,
    PresentationBinding::new(b"canonical request or challenge bytes"),
)?;

let presentation = credential.present(&public, &challenge, &mut rng)?;

// Persist the updated credential before transmitting `presentation`.
// Production verifiers must replace the process-local store used here.
let mut verifier = Verifier::new(public);
let accepted = verifier.verify(&challenge, &presentation)?;
assert_eq!(accepted.tag(), presentation.tag());

# Ok::<(), Box<dyn std::error::Error>>(())
```

The complete runnable version is
[`examples/scoped_rate_limit.rs`](examples/scoped_rate_limit.rs).

## State requirements

Client state is privacy-critical. `Credential::present` advances a counter for
the selected presentation context. Persist the updated credential before
sending the presentation. Restoring an old credential snapshot repeats a tag,
which links the retry and is rejected by a correct server.

`Issuer::key_bytes`, `PendingIssue::to_bytes`, and `Credential::to_bytes` are
unprotected secret-state encodings. The MAYO authenticator does not bind the
credential's counter map. Applications must add confidentiality, integrity,
and rollback protection before persistence. The wire decoder cannot detect a
removed counter record or an older valid snapshot.

Server state is enforcement-critical. `TagStore::insert_if_absent` must be one
linearizable, durable operation shared by every verifier replica for the
scope. The protected application action must occur only after insertion
succeeds. `MemoryTagStore` is for examples and tests only.

Issuer public keys require out-of-band authentication. The
application-context label binds the transcript; it does not certify the key
or replace key distribution, rotation, and revocation.

Each credential has its own cryptographic limit. Issuance and attestation
policy must prevent a principal from obtaining extra credentials for the same
credential epoch.

## Build and test

```sh
scripts/install-hooks.sh
scripts/check.sh quick
scripts/check.sh full
```

The quick check is the pre-commit gate. The full check is the pre-push gate
and includes tests, fuzz-target builds, and dependency audits. Benchmarks are
not gates because their results depend on the host:

```sh
cargo bench --bench protocol --locked
cargo bench --bench side_channels --no-default-features --locked
```

The low-level `binary-fields`, `mayo`, and `voleith` crates are pinned to
commit `e3734dd` of [VOLE-ACT][vole-act]. The default `parallel` feature uses
Rayon; disabling it produces the same transcript sequentially. Rust 1.88 or
newer is required.

See [the protocol paper](paper/vole-arc.tex) for the complete construction,
[the design](docs/DESIGN.md) for the exact implementation relation, and
[the security notes](docs/SECURITY.md) for assumptions and release blockers.
Benchmark methodology and the current machine-specific snapshot are in
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md), and the fuzz targets are described
in [`fuzz/README.md`](fuzz/README.md).

[arc-crypto]: https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/
[arc-protocol]: https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-protocol/
[vole-act]: https://github.com/SamuelSchlesinger/vole-act
