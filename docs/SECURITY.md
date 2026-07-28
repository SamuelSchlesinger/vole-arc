# Security status

VOLE-ARC is a research prototype. Passing tests establishes implementation
consistency for sampled cases; it does not establish a security reduction,
post-quantum security, interoperability, or production readiness.

## Intended properties

Under the assumptions below:

- blind issuance: the issuer does not learn the credential tag key;
- issuance/presentation unlinkability;
- pairwise unlinkability of presentations with distinct hidden nonces;
- deterministic duplicate detection within one effective presentation scope;
- at most `L` accepted presentations per credential and scope; and
- public binding to credential context, presentation context, public limit,
  and request/challenge digest.

Repeated tags are linkable so the verifier can detect rollback and duplicate
presentations.

## What the limit identifies

The limit applies to each valid credential. It does not identify a human,
account, device, installation, or IP address. A principal with `n` credentials
for one credential epoch has up to `n * L` presentations in a bucket.
End-to-end enforcement therefore depends on attestation and issuance quotas.

The relying party must construct `PresentationContext` from trusted policy.
If it accepts an arbitrary client-selected context, the client can choose a
fresh bucket for every request. Epoch identifiers must be canonical and
coarse enough to match the intended window.

`PresentationBinding` is not a bucket. Put per-request challenges there, not
in `PresentationContext`, unless a fresh allowance for every challenge is
actually intended.

## Cryptographic assumptions and proof gaps

The protocol paper now proves a conditional scoped-accounting theorem. For
one effective presentation scope, at most `q * L_max` presentations are
accepted from `q` issued credential lineages, where `L_max` is the largest
limit accepted in that bucket. The proof is structural: it maps each accepted
presentation to an extracted `(lineage, nonce)` pair and uses the atomic tag
store to show that each pair is accepted once. It does not require tag
collision resistance; a tag collision reduces capacity.

The theorem depends on the following assumptions:

1. The selected whipped MAYO public map and exact trapdoor sampler satisfy the
   paper's multi-target auxiliary-preimage one-wayness game. The game gives an
   adversary exact samples on random targets and asks it to invert an
   additional random target.
2. The exact VOLE-in-the-head backend has adaptive multi-theorem,
   straight-line online extraction, zero knowledge, and full-statement
   Fiat-Shamir binding for the composed relations: the hidden SHAKE256
   evaluations, whipped-MAYO verification, and the 32-bit comparison.
3. Domain-separated SHAKE256 behaves as the required hiding commitment,
   keyed tag PRF, collision-resistant hash, and Fiat-Shamir/XOF primitive in
   the relevant model.
4. Randomness used for MAYO keys, hidden credential values, signer salts,
   preimage sampling, and VOLE proofs is cryptographically secure.

In the classical ideal-XOF model, the paper reduces authentication of an
unissued commitment to the MAYO assumption above and gives explicit salt and
credential-collision terms. It also gives a conditional transcript-privacy
hybrid for honest, unexposed credentials with matched public metadata.

This closes the protocol-level counting argument, not the primitive or
implementation proof. The following remain open:

- prove the multi-target auxiliary-preimage assumption from the published
  MAYO foundation, including the exact bounded-retry `SPre` distribution;
- prove adaptive online extraction and multi-theorem zero knowledge for the
  pinned VOLE backend, plus binding of the exact Fiat-Shamir transcript to
  every public statement byte;
- bridge the ideal oracle used in the reduction to the fixed Keccak
  computation inside the circuit;
- give a QROM reduction and complete multi-user concrete bound; and
- independently review the games, reductions, implementation, and parameters.

VOLE-ACT does not supply these results. Pinning its implementation does not
close them.

## Concrete ceilings and parameter choice

MAYO1 and MAYO2 are the only supported protocol parameter sets. The
`ArcParams` trait is sealed accordingly: the VOLE proof layer has
lambda-128 soundness parameters and 128-bit tree seeds, so pairing it with
MAYO3 or MAYO5 would not create a category-3 or category-5 combined suite.

MAYO2 is the default because it is VOLE-ACT's category-1 choice and is
materially faster for this relation. Its `M = 64`-nibble credential
commitment and signed target are 256 bits. A generic collision therefore
costs about `2^128` classical hash evaluations or `2^(256/3) = 2^85.3`
ideal BHT-style quantum queries. Such a collision could give one signed
commitment two credential openings and therefore two scoped tag lineages.

MAYO1 is also category 1, but has `M = 78` nibbles. Its corresponding generic
collision ceilings are about `2^156` classically and `2^104` ideal quantum
queries. It is available when that stronger binding margin justifies its
larger expanded map and slower presentations.

The degree-16 polynomial assertion contributes an error term bounded by

```text
(16 + 1) / 2^128 = 17 / 2^128 ~= 2^-123.91.
```

The full proof bound must also account for vector commitment, consistency,
Fiat-Shamir, MAYO, multi-user, and composition terms.

The pinned VOLE backend uses 128-bit hidden tree seeds and 256-bit proof salts
and commitments. Exhaustive hidden-seed search costs `2^128` classically and
has a `2^64` ideal Grover query ceiling. NIST category-1 comparisons commonly
use AES-128 under quantum search as their reference. A deployment requiring
128 quantum query bits must widen the seeds and version the transcript. The
effect on full-forgery security remains part of the missing reduction.

## State assumptions

### Client

Each credential stores the next nonce for every presentation context. The
updated state must be persisted before a presentation is transmitted.

- `Issuer::key_bytes`, `PendingIssue::to_bytes`, and
  `Credential::to_bytes` are unprotected secret encodings, not sealed storage
  formats.
- The MAYO credential relation authenticates the secret and signature but not
  the counter map. Decoding cannot detect a removed counter, a lower counter,
  or an older authentic snapshot.
- Applications need confidentiality and integrity for these bytes plus a
  monotonic version or equivalent rollback defense. Authenticated encryption
  alone does not reject an older valid ciphertext.
- Rollback repeats a public tag, reducing privacy.
- Concurrent presentation from two copies of the same state can produce the
  same tag; only one can be accepted.
- Silently evicting old context counters is unsafe. The implementation fails
  at `MAX_PRESENTATION_CONTEXTS` instead.
- Credential backups must preserve monotonic counter state. An old backup is
  not a safe recovery point after presentations have escaped.

The server's uniqueness store preserves the rate limit despite client
rollback, provided it has not rolled back too.

### Verifier

`TagStore::insert_if_absent(scope, tag)` must be:

- atomic and linearizable across all verifier replicas;
- durable before returning `true`;
- restored at least as recently as the protected application state; and
- coupled so the protected action occurs only after the first insertion.

`MemoryTagStore` satisfies only single-process sequential test semantics.
Restarting the process forgets all tags.

The verifier inserts only after proof verification. Attackers can therefore
force repeated verification work. Deployments need request-size, CPU,
concurrency, and admission controls.

### Keys

Clients and relying parties must authenticate the issuer public key for the
intended issuer, application, epoch, and profile. The `application_context`
field is a hashed label, not a certificate or proof of key ownership. Issuer
trapdoor bytes require access controls, confidentiality, integrity, backups,
rotation, and revocation.

## Privacy boundaries

Issuer-key encodings contain the MAYO trapdoor. Credential and
pending-issuance encodings contain the hidden tag key, authenticator preimage,
salts, and client counters. They are secret data. Presentation tags, proofs,
contexts, limits, and bindings are public.

Distinct tags are intended to look unlinkable, but implementations can leak
linkage through:

- timing, allocation, CPU-feature, or fault behavior;
- network metadata and application cookies;
- unusual credential contexts, presentation limits, or epoch choices;
- client counter synchronization behavior; and
- issuer or verifier logs.

Locally owned secret buffers, proof witnesses, native Keccak state, credential
intermediates, and decoder staging buffers are best-effort zeroized, including
on error paths guarded by `Zeroizing`. Credential authentication uses
`subtle`'s constant-time equality, and presentation skips a redundant native
MAYO evaluation.

The wrapper cannot wipe copies or temporary allocations inside dependencies.
For example, `mayo::eval` frees signature-dependent vectors without explicit
zeroization. Compiler, allocator, stack, and register copies also remain
outside the wrapper's guarantees. The counter `BTreeMap` is not oblivious;
its allocation and lookup patterns may reveal local usage history to a
same-host or physical observer.

A fixed-vs-fixed timing harness exercises MAYO signing and presentation
proving; the 2026-07-28 run reported `|t| <= 1.076`.

That run is not a constant-time certification. The pinned client prover has
secret-dependent branches in constraint-satisfaction bookkeeping and VOLE
mask construction. `black_box` in the MAYO solver is a compiler barrier, not
a language-level guarantee. No machine-code audit, ctgrind run, power or EM
analysis, fault campaign, or traffic analysis has been performed. The harness
uses same-shape counter maps and does not test counter-history leakage. See
[`BENCHMARKS.md`](BENCHMARKS.md#timing-leakage-diagnostic) for the harness and
exact result.

Three fixture-relative libFuzzer targets cover all seven canonical decoders
for both suites, MAYO2 presentation proofs, MAYO2 issuance-request proofs, and
MAYO2 response authentication. Valid matching public keys exercise the
authenticated paths in the two secret-state decoders.

On 2026-07-28, each target completed a 500-run default-AddressSanitizer smoke
campaign without a crash. This limited regression coverage does not establish
memory safety, denial-of-service resistance, or cryptographic security. See
[`fuzz/README.md`](../fuzz/README.md).

## Interoperability and standards status

The Privacy Pass ARC documents are active work in progress. VOLE-ARC does not
implement their P-256 ciphersuite, keyed verification, serialization, test
vectors, HTTP authentication attributes, or registered token type. It must
not advertise itself as ARC(P-256) or as Privacy Pass interoperable.

There is no independent implementation or byte-level interoperability oracle
for VOLE-ARC. Canonical local encodings and round-trip tests only show internal
agreement.

## Production release gates

Production work still requires:

- a completed and independently reviewed end-to-end security proof;
- independent cryptanalysis of the exact construction and parameters;
- a second implementation and stable external test vectors;
- constant-time, compiler, fault, RNG, and secret-zeroization review;
- sustained, coverage-guided fuzzing of every wire decoder and
  proof-verification entry point;
- crash and multi-replica tests for a durable tag store;
- transactional integration with protected application actions;
- deployment-specific context and credential-issuance policy review; and
- resource limits and operational monitoring that do not introduce linkage.

The timing result, source-level zeroization, and fuzz smoke campaigns do not
satisfy the constant-time, fault, or sustained-fuzzing release gates.
