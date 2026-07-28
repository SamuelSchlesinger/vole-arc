#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

failures=0

report_failure() {
    printf 'hygiene: %s\n' "$1" >&2
    failures=$((failures + 1))
}

required_files=(
    AGENTS.md
    CONTRIBUTING.md
    LICENSE-APACHE
    LICENSE-MIT
    README.md
    docs/DESIGN.md
    docs/SECURITY.md
    paper/vole-arc.tex
    paper/references.bib
    scripts/check.sh
)

for required_file in "${required_files[@]}"; do
    if [[ ! -f "$required_file" ]]; then
        report_failure "missing required project guide: $required_file"
    fi
done

executable_files=(
    .githooks/pre-commit
    .githooks/pre-push
    scripts/build-paper.sh
    scripts/check-hygiene.sh
    scripts/check-paper.sh
    scripts/check.sh
    scripts/install-hooks.sh
)

for executable_file in "${executable_files[@]}"; do
    if [[ ! -x "$executable_file" ]]; then
        report_failure "expected executable bit on $executable_file"
    fi
done

while IFS= read -r -d '' file; do
    case "$file" in
        LICENSE-*|*.bib|*.md|*.rs|*.sh|*.tex|*.toml|*.yaml|*.yml|.editorconfig|.gitignore|.githooks/*)
            ;;
        *)
            continue
            ;;
    esac

    if LC_ALL=C grep -n $'\r$' "$file" >/dev/null; then
        report_failure "$file contains CRLF line endings"
    fi
    if LC_ALL=C grep -n '[[:blank:]]$' "$file" >/dev/null; then
        report_failure "$file contains trailing whitespace"
    fi

    byte_count="$(wc -c < "$file" | tr -d '[:space:]')"
    if ((byte_count > 2097152)); then
        report_failure "$file exceeds the 2 MiB source-file limit"
    fi
done < <(git ls-files --cached --others --exclude-standard -z)

while IFS= read -r dependency_line; do
    if ! printf '%s\n' "$dependency_line" | rg -q 'rev\s*=\s*"[0-9a-f]{40}"'; then
        report_failure "Git dependencies must use a full 40-character revision: $dependency_line"
    fi
done < <(rg -n 'git\s*=' Cargo.toml)

if rg -n 'path\s*=\s*"\.\./' Cargo.toml fuzz/Cargo.toml; then
    report_failure "published manifests must not depend on a sibling checkout"
fi

for check_mode in rust fuzz paper supply-chain; do
    if ! rg -q "scripts/check\\.sh $check_mode" .github/workflows/ci.yml; then
        report_failure "CI does not invoke the canonical '$check_mode' check"
    fi
done

shell_sources=(
    .githooks/pre-commit
    .githooks/pre-push
    scripts/build-paper.sh
    scripts/check-hygiene.sh
    scripts/check-paper.sh
    scripts/check.sh
    scripts/install-hooks.sh
)

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck "${shell_sources[@]}"
else
    report_failure "shellcheck is required"
fi

if ! cargo +1.88.0 metadata --locked --format-version 1 --no-deps >/dev/null; then
    report_failure "Cargo metadata validation failed"
fi

if ((failures != 0)); then
    printf 'hygiene: %d failure(s)\n' "$failures" >&2
    exit 1
fi

printf 'hygiene: clean\n'
