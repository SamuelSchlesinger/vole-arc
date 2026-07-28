# Fuzzing

Build all fuzz targets with:

```sh
cargo +nightly-2026-06-01 fuzz build
```

Run fixture-relative mutation through every canonical decoder:

```sh
cargo +nightly-2026-06-01 fuzz run wire_decode
```

Run proof and authenticator verification against mutations of valid,
deterministic MAYO2 presentations, issuance requests, and issuance responses:

```sh
cargo +nightly-2026-06-01 fuzz run presentation_verify
cargo +nightly-2026-06-01 fuzz run issue_verify
```

`wire_decode` selects and mutates one valid MAYO1 or MAYO2 artifact before
calling its decoder. The artifact may be an issuer key, public key, pending
issuance, request, response, credential, or presentation. The first byte
selects the suite and artifact. Later bytes alter, truncate, or extend the
valid encoding. Each iteration also sends the raw input through all seven
decoders for both suites. Matching public keys let a fresh corpus reach the
secret-state authentication paths.

`presentation_verify` and `issue_verify` are slower because successful parses
enter the VOLE proof verifier or MAYO response authentication. Empty input
exercises a valid presentation or request. The first issuance byte selects a
request or response; later bytes mutate it. Small inputs therefore reach valid
and nearby-invalid paths. Fuzzing is sampled implementation evidence, not a
security proof.
