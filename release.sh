#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=release-lib.sh
source "$ROOT/release-lib.sh"

cd "$ROOT"
load_release_env "$ROOT"
require_signing

VERSION="$(vault_version_name "$ROOT")"
assemble_vault_release "$ROOT"
publish_apk \
  "$ROOT/app/build/outputs/apk/release/app-release.apk" \
  "$ROOT/termux-vault-${VERSION}.apk"
