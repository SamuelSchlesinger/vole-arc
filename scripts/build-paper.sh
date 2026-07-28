#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
destination="${1:-}"
build_root="${TMPDIR:-/tmp}"
build_dir="$(mktemp -d "$build_root/vole-arc-paper.XXXXXX")"

cleanup() {
    rm -rf -- "$build_dir"
}
trap cleanup EXIT

cd "$repo_root"
latexmk \
    -pdf \
    -bibtex \
    -halt-on-error \
    -interaction=nonstopmode \
    -file-line-error \
    -outdir="$build_dir" \
    paper/vole-arc.tex

pdf="$build_dir/vole-arc.pdf"
if [[ ! -s "$pdf" ]]; then
    printf 'paper build did not produce a nonempty PDF\n' >&2
    exit 1
fi

if [[ -n "$destination" ]]; then
    mkdir -p "$(dirname "$destination")"
    install -m 0644 "$pdf" "$destination"
    printf 'Wrote %s\n' "$destination"
fi
