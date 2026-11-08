#!/usr/bin/env bash
# The live bootstrap on Tinfoil, one step per command, each checked before the next.
# It follows the README's Bootstrap section; run the steps in order:
#
#   scripts/live.sh fill AGE1A,AGE1B HEX      put the public keys from docs/KEYS.md in both configs
#   scripts/live.sh preflight                 configs filled, tools present, release exists
#   scripts/live.sh generate                  deploy vault-a from v0.1.1 and generate
#   scripts/live.sh bundle ID [ID ...]        fetch the bundle and rebuild the keyset offline
#   scripts/live.sh commit                    write KEYSET_COMMITMENT into tinfoil-config.yml
#   scripts/live.sh upgrade-a                 vault-a to v0.1.2 through a held candidate
#   scripts/live.sh deploy-b                  vault-b from v0.1.2, pulling from vault-a
#   scripts/live.sh import-s3                 S3 credentials into both vaults
#   scripts/live.sh edge [ABUSE.json POSTMASTER.json]
#                                             deploy the edge, init routing, add role mailboxes
#   scripts/live.sh status                    everything at once, including the shared-host check
#
# It creates and updates Tinfoil containers, but never pushes, tags, or releases on
# GitHub: those stay manual, and each step checks the release it needs exists.
set -euo pipefail

VAULT_REPO=${VAULT_REPO:-fount-labs/fount-mail-vault}
EDGE_REPO=${EDGE_REPO:-fount-labs/fount-mail-edge}
GEN_TAG=${GEN_TAG:-v0.1.1}
TAG=${TAG:-v0.1.2}
EDGE_TAG=${EDGE_TAG:-v0.1.0}
OPERATOR_KEY_FILE=${OPERATOR_KEY_FILE:-$HOME/.fount/operator.key}
EDGE_DIR=${EDGE_DIR:-$(cd "$(dirname "$0")/../../fount-mail-edge" 2>/dev/null && pwd || true)}
STATE=${STATE:-.live-state}

cd "$(dirname "$0")/.."
mkdir -p "$STATE"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }
step() { echo "== $*"; }

vaultctl() { go run ./cmd/vaultctl "$@"; }
edgectl() { (cd "$EDGE_DIR" && go run ./cmd/edgectl "$@"); }

domain() { tinfoil container get "$1" -o json | jq -r .domain; }
status() { curl -sS --max-time 60 "https://$1/status"; }

# wait_for HOST JQ_EXPR SECONDS: poll /status until the jq expression is true.
wait_for() {
  local host=$1 expr=$2 deadline=$((SECONDS + $3)) body
  while ((SECONDS < deadline)); do
    if body=$(status "$host" 2>/dev/null) && jq -e "$expr" >/dev/null 2>&1 <<<"$body"; then
      return 0
    fi
    sleep 10
  done
  echo "last status from $host:" >&2
  status "$host" >&2 || true
  return 1
}

need_release() {
  gh release view "$2" --repo "$1" >/dev/null 2>&1 || fail "$1 has no release $2; cut it first"
}

commitment() {
  [ -s "$STATE/commitment" ] || fail "no commitment yet; run generate"
  cat "$STATE/commitment"
}

config_value() { sed -n "s/^ *- $2: \"\([^\"]*\)\".*/\1/p" "$1"; }
set_config() { sed -i '' "s/^\( *- $2: \)\"[^\"]*\"/\1\"$3\"/" "$1"; }

case "${1:-}" in
  fill)
    (($# == 3)) || fail "usage: fill age1...,age1... OPERATOR_HEX"
    for r in $(tr ',' ' ' <<<"$2"); do
      [[ $r =~ ^age1[02-9ac-hj-np-z]{58}$ ]] || fail "$r isn't an age X25519 recipient"
    done
    [[ $3 =~ ^[0-9a-f]{64}$ ]] || fail "the operator key should be 64 lowercase hex characters"
    [ -n "$EDGE_DIR" ] || fail "can't find fount-mail-edge next to this repo; set EDGE_DIR"
    set_config tinfoil-config.yml RECOVERY_RECIPIENTS "$2"
    set_config tinfoil-config.yml OPERATOR_KEY "$3"
    set_config "$EDGE_DIR/tinfoil-config.yml" OPERATOR_KEY "$3"
    git diff --stat -- tinfoil-config.yml
    git -C "$EDGE_DIR" diff --stat -- tinfoil-config.yml
    pass "public keys in both configs; check the diffs, then commit"
    ;;

  preflight)
    for tool in tinfoil gh jq curl go openssl; do
      command -v "$tool" >/dev/null || fail "$tool isn't installed"
    done
    if grep -n PLACEHOLDER tinfoil-config.yml; then fail "tinfoil-config.yml still has placeholders"; fi
    recipients=$(config_value tinfoil-config.yml RECOVERY_RECIPIENTS)
    threshold=$(config_value tinfoil-config.yml RECOVERY_THRESHOLD)
    count=$(tr ',' '\n' <<<"$recipients" | grep -c '^age1' || true)
    ((count >= threshold)) || fail "$count recipients but threshold $threshold"
    pass "$count recovery recipients, threshold $threshold"
    [ -s "$OPERATOR_KEY_FILE" ] || fail "no operator key at $OPERATOR_KEY_FILE"
    want=$(config_value tinfoil-config.yml OPERATOR_KEY)
    [ -n "$EDGE_DIR" ] && [ "$(config_value "$EDGE_DIR/tinfoil-config.yml" OPERATOR_KEY)" = "$want" ] ||
      fail "the edge's OPERATOR_KEY differs from the vault's"
    pass "OPERATOR_KEY matches in both configs"
    [ -z "$(config_value tinfoil-config.yml KEYSET_COMMITMENT)" ] ||
      echo "note: KEYSET_COMMITMENT is set, so this config can't be $GEN_TAG"
    need_release "$VAULT_REPO" "$GEN_TAG"
    pass "$VAULT_REPO $GEN_TAG is released"
    ;;

  generate)
    need_release "$VAULT_REPO" "$GEN_TAG"
    step "deploying vault-a from $GEN_TAG"
    tinfoil container create vault-a --repo "$VAULT_REPO" --tag "$GEN_TAG"
    a=$(domain vault-a)
    wait_for "$a" '.self_check_error == "" and .release_tag != null' 600 ||
      fail "vault-a didn't pass its self check"
    out=$(curl -sS --max-time 60 -X POST "https://$a/generate")
    c=$(jq -r '.commitment // empty' <<<"$out")
    [ -n "$c" ] || fail "generate answered: $out"
    echo "$c" >"$STATE/commitment"
    pass "vault-a generated keyset $c"
    ;;

  bundle)
    shift
    (($# > 0)) || fail "give the identity files: bundle /Volumes/A/recovery-a.txt"
    a=$(domain vault-a)
    vaultctl bundle -vault "$a" -out keyset.bundle.json
    args=()
    for id in "$@"; do args+=(-identity "$id"); done
    vaultctl check-bundle -bundle keyset.bundle.json "${args[@]}"
    [ "$(jq -r .commitment keyset.bundle.json)" = "$(commitment)" ] || fail "the bundle is for another keyset"
    pass "keyset.bundle.json rebuilds $(commitment); sha256 $(shasum -a 256 keyset.bundle.json | cut -c1-16)"
    echo "Copy keyset.bundle.json to at least two places now, apart from the identities."
    ;;

  commit)
    c=$(commitment)
    for f in tinfoil-config.yml "$EDGE_DIR/tinfoil-config.yml"; do
      set_config "$f" KEYSET_COMMITMENT "$c"
      [ "$(config_value "$f" KEYSET_COMMITMENT)" = "$c" ] || fail "couldn't set KEYSET_COMMITMENT in $f"
      pass "KEYSET_COMMITMENT set in $f"
    done
    echo "Commit both, then release $VAULT_REPO $TAG. The edge's release comes after deploy-b."
    ;;

  upgrade-a)
    need_release "$VAULT_REPO" "$TAG"
    c=$(commitment)
    a=$(domain vault-a)
    step "updating vault-a to $TAG, held"
    tinfoil container update vault-a --tag "$TAG" --hold=true --yes
    wait_for "$a:4443" ".has_keyset and .keyset_commitment == \"$c\" and .release_tag == \"$TAG\"" 900 ||
      fail "the candidate didn't pull the keyset; vault-a is still serving $GEN_TAG, so nothing is lost"
    pass "candidate on $TAG holds $c"
    read -r -p "Promote vault-a to $TAG? [y/N] " ok
    [ "$ok" = y ] || fail "not promoted"
    tinfoil container promote vault-a
    wait_for "$a" ".has_keyset and .release_tag == \"$TAG\"" 600 || fail "vault-a didn't come up on $TAG"
    pass "vault-a serves $TAG with the keyset"
    ;;

  deploy-b)
    c=$(commitment)
    a=$(domain vault-a)
    step "deploying vault-b from $TAG"
    tinfoil container create vault-b --repo "$VAULT_REPO" --tag "$TAG"
    b=$(domain vault-b)
    # It pulls from vault-a by itself at boot.
    wait_for "$b" ".has_keyset and .keyset_commitment == \"$c\"" 900 || fail "vault-b didn't pull the keyset"
    pass "vault-b holds $c"
    ;;

  import-s3)
    [ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_SECRET_ACCESS_KEY:-}" ] ||
      fail "set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to the fount-mail-edge user's key"
    for v in vault-a vault-b; do
      h=$(domain "$v")
      vaultctl import-s3 -vault "$h" -tag "$TAG" -operator-key "$OPERATOR_KEY_FILE"
      wait_for "$h" '.has_s3' 60 || fail "$v has no S3 credentials after the import"
      pass "$v holds the S3 credentials"
    done
    ;;

  edge)
    (($# == 1 || $# == 3)) || fail "usage: edge [ABUSE.json POSTMASTER.json] (each role mailbox's public keys)"
    need_release "$EDGE_REPO" "$EDGE_TAG"
    step "deploying the edge from $EDGE_TAG"
    tinfoil container create edge --repo "$EDGE_REPO" --tag "$EDGE_TAG"
    e=$(domain edge)
    edge_state() { curl -sS --max-time 60 "https://$e/operator/status" | jq -r .routing; }
    deadline=$((SECONDS + 900))
    until [ "$(edge_state 2>/dev/null)" = no-routing-object ]; do
      ((SECONDS < deadline)) || fail "the edge is $(edge_state), want no-routing-object"
      sleep 10
    done
    pass "the edge pulled its keys and waits for init"
    edgectl init -edge "$e" -operator-key "$OPERATOR_KEY_FILE"
    deadline=$((SECONDS + 300))
    until [ "$(edge_state 2>/dev/null)" = serving ]; do
      ((SECONDS < deadline)) || fail "the edge is $(edge_state) after init"
      sleep 5
    done
    pass "the edge is serving"
    if (($# == 1)); then
      echo "abuse@ and postmaster@ aren't provisioned; run edgectl provision before mail can arrive"
      exit 0
    fi
    edgectl provision -edge "$e" -operator-key "$OPERATOR_KEY_FILE" -role abuse -keys "$2"
    edgectl provision -edge "$e" -operator-key "$OPERATOR_KEY_FILE" -role postmaster -keys "$3"
    pass "abuse@ and postmaster@ provisioned"
    ;;

  status)
    for v in vault-a vault-b; do
      h=$(domain "$v" 2>/dev/null) || { echo "$v: not deployed"; continue; }
      echo "$v ($h):"
      status "$h" | jq '{release_tag, has_keyset, keyset_commitment, has_s3, freshness_expires_at,
        self_check_error, chip_id, same_chip_as_last_peer, pending: .recovery.pending_shares,
        refusals: (.refusals // [] | length)}'
    done
    if e=$(domain edge 2>/dev/null); then
      echo "edge ($e): $(curl -sS --max-time 60 "https://$e/operator/status" | jq -r .routing)," \
        "ready: $(curl -sS --max-time 60 "https://$e/ready")"
    fi
    for v in vault-a vault-b edge; do
      printf '%s host: %s\n' "$v" "$(tinfoil container get "$v" -o json 2>/dev/null | jq -r '.host_name // "-"')"
    done
    ;;

  *)
    sed -n '2,15p' "$0"
    exit 2
    ;;
esac
