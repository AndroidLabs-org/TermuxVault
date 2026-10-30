# Shared helpers for release.sh.
# shellcheck shell=bash

load_release_env() {
  local root="$1"
  local env_file="${VAULT_RELEASE_ENV:-$root/.env}"
  if [[ -f "$env_file" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
  fi

  if [[ -z "${JAVA_HOME:-}" && -x /usr/libexec/java_home ]]; then
    JAVA_HOME="$(/usr/libexec/java_home -v 17)"
    export JAVA_HOME
  fi
  export PATH="${JAVA_HOME:+$JAVA_HOME/bin:}$PATH"

  VAULT_SIGNING_STORE_FILE="${VAULT_SIGNING_STORE_FILE:-}"
  VAULT_SIGNING_STORE_PASSWORD="${VAULT_SIGNING_STORE_PASSWORD:-}"
  VAULT_SIGNING_KEY_ALIAS="${VAULT_SIGNING_KEY_ALIAS:-}"
  VAULT_SIGNING_KEY_PASSWORD="${VAULT_SIGNING_KEY_PASSWORD:-}"
  VAULT_SIGNING_STORE_FILE="${VAULT_SIGNING_STORE_FILE/#\~/$HOME}"
}

require_signing() {
  local missing=()
  [[ -n "$VAULT_SIGNING_STORE_FILE" ]] || missing+=("VAULT_SIGNING_STORE_FILE")
  [[ -n "$VAULT_SIGNING_STORE_PASSWORD" ]] || missing+=("VAULT_SIGNING_STORE_PASSWORD")
  [[ -n "$VAULT_SIGNING_KEY_ALIAS" ]] || missing+=("VAULT_SIGNING_KEY_ALIAS")
  [[ -n "$VAULT_SIGNING_KEY_PASSWORD" ]] || missing+=("VAULT_SIGNING_KEY_PASSWORD")
  if ((${#missing[@]})); then
    echo "Missing signing settings: ${missing[*]}" >&2
    echo "Copy .env.example to .env and fill in local values," >&2
    echo "or export them / set VAULT_RELEASE_ENV to another env file." >&2
    exit 1
  fi
  if [[ ! -f "$VAULT_SIGNING_STORE_FILE" ]]; then
    echo "Signing store not found: $VAULT_SIGNING_STORE_FILE" >&2
    exit 1
  fi
}

vault_version_name() {
  local root="$1"
  local version
  version="$(sed -n 's/^[[:space:]]*versionName = "\([^"]*\)".*/\1/p' \
    "$root/app/build.gradle.kts" | head -1)"
  if [[ -z "$version" ]]; then
    echo "Could not read versionName from app/build.gradle.kts" >&2
    exit 1
  fi
  printf '%s\n' "$version"
}

assemble_vault_release() {
  local root="$1"
  (
    cd "$root"
    ./gradlew --quiet lintRelease testDebugUnitTest
    ./gradlew assembleRelease \
      -PvaultSigningStoreFile="$VAULT_SIGNING_STORE_FILE" \
      -PvaultSigningStorePassword="$VAULT_SIGNING_STORE_PASSWORD" \
      -PvaultSigningKeyAlias="$VAULT_SIGNING_KEY_ALIAS" \
      -PvaultSigningKeyPassword="$VAULT_SIGNING_KEY_PASSWORD"
  )
}

publish_apk() {
  local source_apk="$1"
  local destination_apk="$2"
  if [[ ! -f "$source_apk" ]]; then
    echo "Built APK not found: $source_apk" >&2
    exit 1
  fi
  cp "$source_apk" "$destination_apk"
  echo "Signed release APK: $destination_apk"
  ls -lh "$destination_apk"
}
