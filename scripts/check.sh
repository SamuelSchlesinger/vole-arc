#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

rust_toolchain="1.88.0"
nightly_toolchain="nightly-2026-06-01"

usage() {
    printf 'usage: %s {hygiene|lint|test|rust|paper|fuzz|supply-chain|quick|full}\n' "$0" >&2
}

run_hygiene() {
    scripts/check-hygiene.sh
}

run_lint() {
    cargo +"$rust_toolchain" fmt --check
    cargo +"$rust_toolchain" clippy --all-targets --all-features --locked -- -D warnings
}

run_tests() {
    cargo +"$rust_toolchain" test --locked
    cargo +"$rust_toolchain" test --no-default-features --locked
    RUSTDOCFLAGS="-D warnings" cargo +"$rust_toolchain" doc --no-deps --locked
}

run_paper() {
    scripts/check-paper.sh
}

run_fuzz() {
    cargo +"$nightly_toolchain" fmt --manifest-path fuzz/Cargo.toml --check
    cargo +"$nightly_toolchain" fuzz build
    cargo +"$nightly_toolchain" clippy \
        --manifest-path fuzz/Cargo.toml \
        --bins \
        --locked \
        -- \
        -D warnings
}

run_supply_chain() {
    cargo deny --all-features check
    cargo audit --file Cargo.lock
    cargo audit --file fuzz/Cargo.lock
}

mode="${1:-}"
case "$mode" in
    hygiene)
        run_hygiene
        ;;
    lint)
        run_lint
        ;;
    test)
        run_tests
        ;;
    rust)
        run_lint
        run_tests
        ;;
    paper)
        run_paper
        ;;
    fuzz)
        run_fuzz
        ;;
    supply-chain)
        run_supply_chain
        ;;
    quick)
        run_hygiene
        run_lint
        run_paper
        ;;
    full)
        run_hygiene
        run_lint
        run_tests
        run_paper
        run_fuzz
        run_supply_chain
        ;;
    *)
        usage
        exit 2
        ;;
esac
