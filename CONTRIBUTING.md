# Contributing to VOLE-ARC

VOLE-ARC is an unaudited cryptographic research prototype. Changes should make
the implementation easier to review and should state their trust boundary
plainly.

## Set up the repository

Install Rust 1.88.0, nightly-2026-06-01, ShellCheck, ChkTeX, Latexmk, Poppler,
`cargo-deny`, `cargo-audit`, and `cargo-fuzz`. Then install the tracked hooks:

```sh
scripts/install-hooks.sh
```

The pre-commit hook runs `scripts/check.sh quick`. The pre-push hook runs the
complete suite with `scripts/check.sh full`. CI calls the same component
commands, so local and hosted checks share one definition.

## Check commands

| Command | Coverage |
|---|---|
| `scripts/check.sh hygiene` | Source hygiene, dependency pins, manifests, hooks, and shell scripts |
| `scripts/check.sh lint` | Rustfmt and Clippy for all targets and features |
| `scripts/check.sh test` | Default and sequential tests plus warning-free Rustdoc |
| `scripts/check.sh paper` | ChkTeX, LaTeX build, and extracted-PDF sanity checks |
| `scripts/check.sh fuzz` | Fuzz-target formatting, build, and Clippy |
| `scripts/check.sh supply-chain` | License, source, advisory, and dependency-policy checks |
| `scripts/check.sh quick` | Hygiene, Rust lints, and paper checks |
| `scripts/check.sh full` | Every check above |

Build a review copy of the protocol note with:

```sh
scripts/build-paper.sh output/pdf/vole-arc-protocol.pdf
```

Generated PDFs and LaTeX intermediates are intentionally ignored.

## Review protocol changes

Before requesting review, answer each applicable question:

- Does witness construction still match the circuit, bit order, padding, and
  public statement exactly?
- Are issuer, credential, presentation, limit, binding, suite, profile, and
  version values bound in the intended transcript?
- Could a new context, epoch, retry, rollback, or limit change reset or expand
  a bucket unexpectedly?
- Are state transitions persisted before transmission, and is duplicate
  insertion atomic and durable across replicas?
- Are lengths, counts, suite identifiers, reserved bytes, and trailing data
  rejected before unsafe allocation or expensive verification?
- Are secret buffers, error paths, dependency copies, branches, and memory
  access patterns treated consistently with the side-channel claims?
- Do deterministic vectors, negative tests, fuzz fixtures, examples,
  benchmarks, design notes, security notes, and the paper need an update?
- Does the change alter a cryptographic assumption, concrete security ceiling,
  wire format, or production-release gate?

Record what the checks establish and what they do not. In particular, green
tests, fuzz campaigns, and timing diagnostics do not constitute a reduction,
cryptographic audit, or constant-time certification.
