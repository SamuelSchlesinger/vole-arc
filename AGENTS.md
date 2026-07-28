# Repository instructions

VOLE-ARC is security-sensitive research cryptography. Treat every protocol,
serialization, state-management, and parameter change as a security change.
Passing tests is necessary, but it is not a security proof or an audit.

## Read before changing protocol code

Read these files before editing `src/context.rs`, `src/circuit.rs`,
`src/keccak.rs`, `src/protocol.rs`, `src/store.rs`, or `src/wire.rs`:

1. `README.md`
2. `docs/DESIGN.md`
3. `docs/SECURITY.md`
4. `paper/vole-arc.tex`
5. the relevant tests and dependency APIs

Use the implementation and deterministic wire tests as the source of truth for
current behavior. Keep the design note, security note, paper, examples,
benchmarks, fuzz fixtures, and public API documentation synchronized with it.

## Invariants to preserve

- Keep every public context in the Fiat-Shamir statement and every secret
  value in both witness generation and circuit constraints.
- Domain-separate and version every transcript. A transcript or relation
  change requires a protocol or wire version decision and updated vectors.
- Keep presentation contexts server-selected and stable for the intended
  relying-party, purpose, and epoch bucket. Per-request data belongs in the
  presentation binding.
- Preserve the hidden `counter < limit` constraint and the atomic,
  durable-before-success `TagStore::insert_if_absent` contract.
- Treat credential and issuer encodings as secret, unauthenticated storage
  containers unless the API explicitly verifies them. Counter rollback must
  remain an application-visible risk.
- Reject malformed lengths and parameter identifiers before allocation or
  cryptographic work. Preserve canonical decoding and trailing-byte rejection.
- Do not add a suite whose strongest component exceeds the 128-bit VOLE
  backend without defining and analyzing a new combined suite.
- Do not claim constant-time behavior, a complete reduction, post-quantum
  security, Privacy Pass interoperability, or production readiness without
  evidence that closes the corresponding gap in `docs/SECURITY.md`.

## Required checks

Install the tracked hooks once with `scripts/install-hooks.sh`.

- During development: `scripts/check.sh quick`
- Before handoff or push: `scripts/check.sh full`
- Paper artifact: `scripts/build-paper.sh output/pdf/vole-arc-protocol.pdf`

Do not bypass a hook by weakening a lint, deleting a test, or adding a blanket
allow. A narrow exception is acceptable only when the code documents why the
lint is inapplicable.

Do not commit generated PDF or LaTeX intermediate files. Do not push unless the
user explicitly requests it.
