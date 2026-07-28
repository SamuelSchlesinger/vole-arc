# VOLE-ARC design

## Goal

VOLE-ARC gives one anonymously issued credential an independent allowance in
each public presentation context. A presentation reveals a pseudorandom tag
and a zero-knowledge proof. It does not reveal the credential, its issuance
transcript, its secret, or the counter used to form the tag.

The construction uses ARC's four-step structure:

1. issue a long-lived hidden credential once;
2. derive a deterministic tag from a credential secret, public presentation
   context, and bounded nonce;
3. prove the nonce is in a server-selected range; and
4. reject repeated tags.

It reuses VOLE-ACT's signer-salted MAYO authenticator and VOLE-in-the-head
proof backend. It does not reuse ACT's balance or token-refresh protocol.

## Public inputs and domains

An issuer key has:

- an expanded MAYO public map `P*` and trapdoor;
- a VOLE performance profile; and
- arbitrary application/key-epoch bytes.

These values are hashed into a 32-byte issuer context `I`.

Applications separately construct:

- credential context `Cctx`, normally an attestation class or credential
  epoch;
- presentation context `Pctx`, the stable rate-limit bucket;
- binding `B`, normally a digest of one challenge or protected request; and
- nonzero presentation limit `L`, a `u32`.

All application inputs use domain-separated, length-framed hashes.
`PresentationContext::scoped(rp, purpose, epoch)` is a convenience constructor.
A deployment can instead hash any canonical bucket description with
`PresentationContext::new`. An epoch-presence byte distinguishes `None` from
`Some(b"")`.

Two derived scopes keep the in-circuit SHAKE inputs within one 136-byte
SHAKE256 rate block:

```text
CS = SHAKE256("VOLE-ARC/credential-scope/v1" || I || Cctx, 32)
PS = SHAKE256("VOLE-ARC/presentation-scope/v1" || I || Cctx || Pctx, 32)
```

`PS` excludes `B` and `L`: a new request binding does not reset the bucket,
and a limit change applies to the same nonce namespace.

## Key generation

The issuer runs MAYO trapdoor generation and derives `I` from the application
context, expanded public map, MAYO parameter set, protocol version, 32-bit
counter width, and VOLE profile.

MAYO2 is the API default and VOLE-ACT's category-1 choice. MAYO1 is slower but
has a wider credential-hash output and a higher generic collision ceiling.
The issuer context and wire envelope bind the parameter set. The public
`ArcParams` trait is sealed to MAYO1 and MAYO2 because the combined protocol
uses a lambda-128 VOLE suite and 128-bit proof-tree seeds. Pairing that proof
layer with MAYO3 or MAYO5 would not create a higher-security VOLE-ARC suite.

The public key contains the application context and expanded MAYO map. The
private key contains the MAYO trapdoor and the same public configuration.

## Credential issuance

The client samples independent uniform values:

```text
k   <- {0,1}^256    hidden tag key
rho <- {0,1}^256    commitment hiding nonce
```

It computes the `P::M`-nibble commitment

```text
C = Prefix_M(
      SHAKE256("VOLE-ARC/credential/v1" || CS || k || rho)
    ).
```

The issuance request contains `C` and a VOLE-in-the-head proof of knowledge of
`(k, rho)` satisfying that equation. `I`, `Cctx`, and `C` are in the
Fiat-Shamir statement.

After verifying the proof, the issuer samples a fresh 256-bit salt `zeta` and
computes

```text
T = Prefix_M(
      SHAKE256("VOLE-ARC/signed/v1" || pack16(C) || zeta)
    ).
sigma <- SPre(mayo_secret_key, T)
```

The response is `(sigma, zeta)`. The client checks
`P*(sigma) = T` before storing

```text
credential = (I, Cctx, sigma, k, rho, zeta, counters = {}).
```

Repeatedly inverting one client-selected MAYO target would require a different
one-more-preimage assumption and simulator. By sampling `zeta` after request
acceptance, the signer gets a fresh hash-then-invert target. The protocol paper
reduces authentication of a new commitment to a multi-target
auxiliary-preimage one-wayness game for the raw whipped MAYO map and exact
`SPre` sampler in the classical ideal-XOF model. That game is an explicit
candidate assumption; it is not established by standard MAYO signature
security.

Repeated responses to one issuance request have different salts and
authenticators but the same `(k, rho)`. They therefore produce the same scoped
tags and remain one rate-limit lineage.

## Presentation

For `Pctx`, the client reads its next hidden nonce `i`, initially zero. It
rejects locally if `i >= L`. It computes

```text
tag = SHAKE256("VOLE-ARC/tag/v1" || k || PS || le32(i), 32).
```

The presentation proof establishes knowledge of
`(sigma, k, rho, zeta, i)` such that:

```text
C  = CredentialHash(CS, k, rho)
T  = SignedCredentialHash(C, zeta)
P*(sigma) = T
tag = TagHash(k, PS, i)
0 <= i < L
```

The public Fiat-Shamir statement contains:

```text
protocol version, MAYO parameter set, I, Cctx, Pctx, L, B, tag.
```

`B` is transcript-only: it does not enter the tag domain or witness equations.
The scoped cap therefore does not depend on it, while the claim that a proof
cannot transfer to a different `B` depends on full-statement Fiat-Shamir
binding.

The nonce is bit-decomposed inside the circuit. To prove `i < L`, the circuit
computes the carry chain for `i + !L + 1` and constrains the final carry to
zero. The final carry is one exactly when `i >= L`.

After proof construction succeeds, the client advances the counter for
`Pctx`. The proof result is `(tag, proof)`; the nonce is not transmitted.

## Verification and the rate-limit argument

The verifier reconstructs `CS` and `PS` from its trusted public key and
challenge policy, then verifies the proof. It atomically inserts `(PS, tag)`
into a durable uniqueness store. Only the first insertion can authorize the
protected action.

Assuming online proof extraction, authenticated-commitment unforgeability,
binding of the credential hash, and a linearizable durable store:

1. every accepted presentation extracts to an issued credential lineage;
2. its nonce is one of the `L` integers in `[0, L)`;
3. `(k, PS, i)` determines one tag; and
4. the store accepts a tag once.

One credential has at most `L` accepted presentations for `PS`.
With `q` issued lineages the bound is `q * L`. If accepted challenges under
one `PS` use different limits, replace `L` with the largest accepted limit.

Tag collision resistance is not needed for this upper bound. A collision on
two distinct tag inputs makes the store merge uses, which reduces capacity or
causes denial of service. The binding requirement is instead that one
authenticated commitment cannot open to distinct credential-hash inputs and
therefore distinct tag keys.

Changing `L` does not create a new tag domain. If a server first uses `L=5`
and later `L=10`, nonces `0..4` retain their old tags and only `5..9` add
capacity. A new `Pctx`, including a new relying party or epoch, creates a
separate allowance.

## State and retry boundaries

The client counter map is part of the credential's canonical secret-state
encoding, but it is not authenticated by the MAYO credential relation.
`Issuer::key_bytes`, `PendingIssue::to_bytes`, and `Credential::to_bytes`
provide canonical bytes, not confidentiality, integrity, or rollback
protection. The application must seal them and separately enforce monotonic
recovery. The client should:

1. construct the presentation;
2. persist the incremented credential atomically; and
3. only then transmit the presentation.

A crash or rollback between these steps may repeat a tag. That reveals a
duplicate and the verifier rejects it; it does not add capacity.

The verifier's `TagStore::insert_if_absent` must be linearizable and durable
across replicas. An accepted presentation does not make an exact replay safe.
HTTP or application retry semantics must be coupled to the protected action's
transaction.

## Relationship to Privacy Pass ARC

The March 2026 ARC drafts use a P-256 keyed-verification anonymous credential,
a context-derived group element, a tag of the form
`(m1 + nonce)^-1 * generatorT`, and an integrated range proof. The Privacy
Pass protocol maps issuer, origin, credential, and redemption fields into the
request and presentation contexts.

VOLE-ARC retains ARC's scoped rate-limit structure: a credential-bound secret,
a deterministic `(secret, context, nonce)` tag, and a proof that the nonce is
below a public limit. The constructions differ as follows:

- MAYO and VOLE-in-the-head replace P-256 and Schnorr proofs;
- verification is public rather than keyed;
- the tag is a SHAKE256 PRF-style output rather than a group element;
- the nonce remains hidden and is absent from the wire artifact;
- contexts are opaque application digests rather than Privacy Pass TLS
  structures; and
- wire envelopes use `VARC`, not Privacy Pass token type `0xE5AC`.

VOLE-ARC is an ARC-inspired candidate construction. It is not an alternate
ciphersuite or an interoperable Privacy Pass implementation.
