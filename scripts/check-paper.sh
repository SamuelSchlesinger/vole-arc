#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
check_root="${TMPDIR:-/tmp}"
check_dir="$(mktemp -d "$check_root/vole-arc-paper-check.XXXXXX")"

cleanup() {
    rm -rf -- "$check_dir"
}
trap cleanup EXIT

cd "$repo_root"

required_commands=(chktex latexmk pdfinfo pdftotext)
for required_command in "${required_commands[@]}"; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        printf 'paper: missing required command: %s\n' "$required_command" >&2
        exit 1
    fi
done

# ChkTeX 13 misreads protocol acronyms before punctuation, and 36 rejects the
# conventional ciphersuite spelling ARC(P-256). The other disabled checks are
# TeX command-spacing rules that conflict with the document's macro style.
chktex -q -n 1 -n 8 -n 13 -n 24 -n 36 paper/vole-arc.tex

pdf="$check_dir/vole-arc-protocol.pdf"
scripts/build-paper.sh "$pdf"

pages="$(pdfinfo "$pdf" | awk '/^Pages:/ { print $2 }')"
if [[ -z "$pages" ]] || ((pages < 1)); then
    printf 'paper: generated PDF has no pages\n' >&2
    exit 1
fi

text="$check_dir/vole-arc-protocol.txt"
pdftotext "$pdf" "$text"
normalized_text="$check_dir/vole-arc-protocol-normalized.txt"
tr '\n\f\r\t' '    ' < "$text" | tr -s ' ' > "$normalized_text"
required_phrases=(
    "VOLE-ARC: Scoped Anonymous Rate-Limited Credentials"
    "Protocol specification"
    "Security status and open proof obligations"
    "Scoped-accounting theorem"
    "Multi-target auxiliary-preimage one-wayness"
    "not wire-compatible"
)
for required_phrase in "${required_phrases[@]}"; do
    if ! rg -Fq "$required_phrase" "$normalized_text"; then
        printf 'paper: generated PDF is missing expected text: %s\n' "$required_phrase" >&2
        exit 1
    fi
done

printf 'paper: clean (%s pages)\n' "$pages"
