# Benchmark methodology and snapshot

Run the statistically sampled protocol suite with:

```sh
cargo bench --bench protocol --locked
```

Run the fixed-vs-fixed timing diagnostic separately, single-threaded, with:

```sh
cargo bench --bench side_channels --no-default-features --locked
```

The protocol suite uses Criterion 0.5.1 with flat sampling, a one-second
warm-up, ten samples, and a three-second measurement window. The benchmark
profile enables thin LTO and debug symbols. Results are single-operation
latencies on an otherwise lightly loaded machine, not sustained concurrent
throughput.

Seeded `StdRng` streams make the fixtures reproducible and exclude OS entropy
acquisition from the timings. Deployments still require a CSPRNG. Issuer
iterations verify one valid request and generate a fresh salt and MAYO
preimage. Presentation iterations advance a real credential counter under a
`u32::MAX` limit. The verifier-and-store benchmark includes the store trait
call but excludes database, network, replication, and durability latency.

## Snapshot: 2026-07-28

Environment: MacBook Pro `Mac16,8`, Apple M4 Pro (14 cores), 48 GB RAM,
macOS 26.5.2 (`25F84`), `aarch64-apple-darwin`,
`rustc 1.99.0-nightly (d0babd8b6 2026-07-15)`, LLVM 22.1.8. Default
features, including parallel GGM tree work, were enabled for protocol
measurements.

The table gives Criterion mean point estimates and 95% confidence intervals
for the balanced profile. MAYO2 is the crate default; MAYO1 remains available
when its wider credential-hash output is worth the additional cost.

| Operation | MAYO2 | MAYO1 |
|---|---:|---:|
| Issuer key generation | 19.34 ms `[19.20, 19.48]` | 109.20 ms `[105.14, 114.82]` |
| Issue: client prove | 8.44 ms `[8.41, 8.47]` | 8.67 ms `[8.63, 8.71]` |
| Issue: issuer verify and sign | 3.21 ms `[3.18, 3.25]` | 6.07 ms `[6.05, 6.10]` |
| Issue: end to end | 13.28 ms `[13.11, 13.53]` | 18.50 ms `[18.44, 18.57]` |
| Presentation: client prove | 26.48 ms `[26.39, 26.59]` | 38.44 ms `[38.30, 38.58]` |
| Presentation: proof verification | 7.37 ms `[7.32, 7.42]` | 15.62 ms `[15.59, 15.65]` |
| Presentation: verify and store call | 7.15 ms `[7.13, 7.17]` | 15.60 ms `[15.58, 15.62]` |
| Presentation: end to end | 33.86 ms `[33.75, 33.97]` | 54.61 ms `[54.43, 54.78]` |

The MAYO2 end-to-end issuance row was remeasured with a two-second warm-up,
50 samples, and a ten-second measurement window:

```sh
cargo bench --bench protocol --locked -- \
  --sample-size 50 --warm-up-time 2 --measurement-time 10 \
  'balanced/issue/end-to-end/MAYO2'
```

MAYO preimage sampling has a retry tail, so a larger sample is more
representative than the default ten-sample characterization for that row.

## VOLE profile tradeoff

For the default MAYO2 parameter set:

| Profile | Issue prove | Presentation prove | Issue request | Presentation |
|---|---:|---:|---:|---:|
| Compact | 9.75 ms | 29.26 ms | 29,750 B | 71,382 B |
| Balanced | 8.66 ms | 26.85 ms | 55,286 B | 138,550 B |
| Low latency | 8.75 ms | 27.19 ms | 106,358 B | 272,886 B |

Balanced was marginally faster than the nominal low-latency profile on this
machine while producing roughly half-size proofs, so it remains the default.
The profile names describe tree geometry, not a guarantee that every CPU and
circuit will preserve that latency ordering.

The balanced MAYO2 fixture also produced:

| Artifact | Bytes |
|---|---:|
| Expanded public key envelope | 106,329 |
| Issue response | 203 |
| Credential with one scoped counter | 371 |
| Presentation | 138,550 |

Wire-only codec costs were microseconds except where decoding performs
cryptographic work: credential decode and authentication was 1.10 ms, and
public-key decode plus compact circuit derivation was 13.51 ms.

## Timing-leakage diagnostic

The side-channel harness randomizes two fixed secret classes, measures each
operation with independent RNG streams, and reports Welch's t statistic. The
2026-07-28 single-threaded run produced:

| Secret-bearing operation | Samples per class | Welch t |
|---|---:|---:|
| MAYO1 preimage sampling | 2,000 | -1.076 |
| MAYO2 preimage sampling | 2,000 | -0.862 |
| MAYO2 presentation proving | 128 | 1.044 |

No class separation crossed the dudect-style `|t| >= 4.5` investigation
threshold. This found no signal for one compiler, machine, and input
partition. It does not establish constant-time behavior and does not replace a
compiler audit, ctgrind run, power or EM analysis, or fault analysis.

## Snapshot boundary

The dependency pin `e3734dd` uses 16-byte vector-commitment tree seeds and
32-byte salts and commitments. Any proof-tree width or transcript-version
change invalidates both the timings and wire sizes above and requires a fresh
run. Criterion's raw reports are generated under `target/criterion/` and are
not source artifacts.
