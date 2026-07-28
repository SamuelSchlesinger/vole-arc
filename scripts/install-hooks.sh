#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

git config --local core.hooksPath .githooks

configured_path="$(git config --local --get core.hooksPath)"
if [[ "$configured_path" != ".githooks" ]]; then
    printf 'failed to configure core.hooksPath\n' >&2
    exit 1
fi

printf 'Installed VOLE-ARC hooks from .githooks\n'
printf '  pre-commit: scripts/check.sh quick\n'
printf '  pre-push:   scripts/check.sh full\n'
