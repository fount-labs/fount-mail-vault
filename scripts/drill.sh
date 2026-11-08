#!/usr/bin/env bash
# The drills in docs/DRILLS.md, one step per command. Every step that changes a live
# container asks first, and only the owner runs those.
#
#   scripts/drill.sh preflight                   witness margin, both vaults agree, container count
#   scripts/drill.sh restart vault-b|vault-a     stop and redeploy one vault; it must pull the same keyset
#   scripts/drill.sh bundle-check BUNDLE ID      offline only: rebuild the keyset from a bundle copy
#   scripts/drill.sh recovery-status HOST        after the shares: what the drill vault holds
#   scripts/drill.sh routing-fetch               download the newest routing backup
#   scripts/drill.sh routing-verify FILE         edgectl restore without -write
#   scripts/drill.sh routing-refuse FILE         -write without -replace; a serving edge must refuse it
#   scripts/drill.sh routing-write FILE          -write -replace on the serving edge, then wait for serving
#
# Results go in $STATE, which is gitignored, and into "The live run" in fount-mail-vault.md.
set -euo pipefail

TAG=${TAG:-v0.1.2}
OPERATOR_KEY_FILE=${OPERATOR_KEY_FILE:-$HOME/.fount/operator.key}
EDGE_DIR=${EDGE_DIR:-$(cd "$(dirname "$0")/../../fount-mail-edge" 2>/dev/null && pwd || true)}
AWS_PROFILE=${AWS_PROFILE:-fount-mail-prod}
MARGIN_S=${MARGIN_S:-172800} # the watch's two-day witness margin
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
up() { curl -fsS --max-time 20 "https://$1/health" >/dev/null 2>&1; }
edge_state() { curl -sS --max-time 60 "https://$1/operator/status" | jq -r .routing; }
config_value() { sed -n "s/^ *- $2: \"\([^\"]*\)\".*/\1/p" "$1"; }
stamp() { date -u +%Y%m%dT%H%M%SZ; }

confirm() {
  read -r -p "$1 [y/N] " ok
  [ "$ok" = y ] || fail "stopped before: $1"
}

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

wait_for_edge() {
  local host=$1 want=$2 deadline=$((SECONDS + $3))
  until [ "$(edge_state "$host" 2>/dev/null)" = "$want" ]; do
    ((SECONDS < deadline)) || return 1
    sleep 10
  done
}

want_commitment() {
  local c
  c=$(config_value tinfoil-config.yml KEYSET_COMMITMENT)
  [ -n "$c" ] || fail "tinfoil-config.yml has no KEYSET_COMMITMENT"
  echo "$c"
}

# healthy HOST: holds the committed keyset on $TAG, self check clean, and the witness
# has more than MARGIN_S left.
healthy() {
  local body
  body=$(status "$1") || fail "$1 doesn't answer /status"
  jq -e --arg c "$(want_commitment)" --arg t "$TAG" --argjson m "$MARGIN_S" '
    .has_keyset and .keyset_commitment == $c and .release_tag == $t and .self_check_error == ""
    and ((.freshness_expires_at | sub("\\.[0-9]+"; "") | fromdateiso8601) - now > $m)' >/dev/null <<<"$body" ||
    { echo "$body" | jq '{release_tag, has_keyset, keyset_commitment, self_check_error, freshness_expires_at}' >&2
      fail "$1 isn't healthy enough to drill against"; }
}

# no_variables NAME: deploy-time variables aren't measured, so a drill only redeploys
# a container whose saved map is empty.
no_variables() {
  local vars
  vars=$(tinfoil container get "$1" -o json | jq -r '.variables // "" | @base64d')
  [ "$vars" = "{}" ] || [ -z "$vars" ] || fail "$1 has saved deploy-time variables: $vars"
}

other() { [ "$1" = vault-a ] && echo vault-b || echo vault-a; }

backup_bucket() {
  [ -n "$EDGE_DIR" ] || fail "can't find fount-mail-edge next to this repo; set EDGE_DIR"
  config_value "$EDGE_DIR/tinfoil-config.yml" S3_BACKUP_BUCKET
}

case "${1:-}" in
  preflight)
    for tool in tinfoil jq curl go aws; do
      command -v "$tool" >/dev/null || fail "$tool isn't installed"
    done
    for v in vault-a vault-b edge; do no_variables "$v"; done
    pass "no deploy-time variables on vault-a, vault-b or edge"
    for v in vault-a vault-b; do
      healthy "$(domain "$v")"
      pass "$v holds $(want_commitment) on $TAG, witness until $(status "$(domain "$v")" | jq -r .freshness_expires_at)"
    done
    running=$(tinfoil container list -o json | jq '[.[] | select(.status | ascii_downcase == "running")] | length')
    echo "running containers: $running of 5"
    ((running <= 4)) || echo "note: no spare slot for the recovery drill's vault"
    e=$(domain edge)
    echo "edge: $(edge_state "$e")"
    ;;

  restart)
    (($# == 2)) && [[ $2 == vault-a || $2 == vault-b ]] || fail "usage: restart vault-a|vault-b"
    v=$2 peer=$(other "$2")
    h=$(domain "$v") p=$(domain "$peer")
    healthy "$p"
    no_variables "$v"
    pass "$peer holds the keyset, so $v can go"
    before=$(status "$h")
    echo "$before" >"$STATE/drill-$(stamp)-$v-before.json"
    old_fp=$(jq -r .transfer_key_fp <<<"$before")
    confirm "Stop $v and redeploy it from its saved config?"
    step "stopping $v"
    tinfoil container stop "$v"
    deadline=$((SECONDS + 300))
    while up "$h"; do
      ((SECONDS < deadline)) || fail "$v still answers after stop"
      sleep 5
    done
    pass "$v is down; its keyset is gone with its memory"
    step "deploying $v"
    tinfoil container deploy "$v"
    wait_for "$h" ".has_keyset and .keyset_commitment == \"$(want_commitment)\" and .release_tag == \"$TAG\"" 900 ||
      fail "$v didn't pull the keyset back; $peer still holds it, so leave $peer alone"
    after=$(status "$h")
    echo "$after" >"$STATE/drill-$(stamp)-$v-after.json"
    new_fp=$(jq -r .transfer_key_fp <<<"$after")
    jq -e --arg p "https://$p" '.source == "pulled from " + $p' >/dev/null <<<"$after" ||
      fail "$v's source is $(jq -r .source <<<"$after"), want pulled from $p"
    jq -e '.has_s3 and .self_check_error == ""' >/dev/null <<<"$after" || fail "$v came back without S3 or with a self-check error"
    [ "$new_fp" != "$old_fp" ] || fail "$v kept its transfer key, so it didn't reboot"
    peer_saw=$(status "$p" | jq -r '.last_peer | "\(.kind) \(.key_fingerprint) \(.tag)"')
    [ "$peer_saw" = "vault $new_fp $TAG" ] || fail "$peer's last peer is '$peer_saw', want 'vault $new_fp $TAG'"
    pass "$v pulled $(want_commitment) from $peer with a new transfer key $new_fp, and has S3"
    status "$p" | jq '{refusals: (.refusals // [] | length), same_chip_as_last_peer}'
    ;;

  bundle-check)
    (($# == 3)) || fail "usage: bundle-check BUNDLE /Volumes/X/recovery-x.txt"
    route -n get default >/dev/null 2>&1 && fail "the network is up; turn Wi-Fi off and unplug Ethernet first"
    [[ $3 == /Volumes/* ]] || fail "$3 isn't on a removable drive; identities never go on the internal disk"
    [ -x ./vaultctl ] || fail "build ./vaultctl before going offline: go build -trimpath -o vaultctl ./cmd/vaultctl"
    ./vaultctl check-bundle -bundle "$2" -identity "$3"
    got=$(jq -r .commitment "$2")
    [ "$got" = "$(want_commitment)" ] || fail "$2 is for keyset $got"
    pass "$2 ($(shasum -a 256 "$2" | cut -c1-16)) rebuilds $(want_commitment) with $(basename "$3")"
    echo "Eject the drive before turning the network back on."
    ;;

  recovery-status)
    (($# == 2)) || fail "usage: recovery-status HOST"
    body=$(status "$2")
    echo "$body" >"$STATE/drill-$(stamp)-recovery.json"
    jq '{release_tag, has_keyset, keyset_commitment, source, has_s3, pending: .recovery.pending_shares,
      refusals: (.refusals // [] | length), self_check_error}' <<<"$body"
    jq -e --arg c "$(want_commitment)" '.has_keyset and .keyset_commitment == $c
      and .source == "restored from recovery shares"' >/dev/null <<<"$body" ||
      fail "$2 hasn't restored the committed keyset from shares"
    pass "$2 restored $(want_commitment) from shares; delete it now"
    ;;

  routing-fetch)
    bucket=$(backup_bucket)
    versions=$(aws --profile "$AWS_PROFILE" s3api list-object-versions --bucket "$bucket" --prefix routing/current \
      --query 'Versions[?Key==`routing/current`]' --output json)
    n=$(jq 'length' <<<"${versions:-null}" 2>/dev/null || echo 0)
    ((n > 0)) || fail "$bucket has no routing backup yet; the first mailbox change writes one"
    id=$(jq -r '.[] | select(.IsLatest) | .VersionId' <<<"$versions")
    out="$STATE/routing-$id"
    aws --profile "$AWS_PROFILE" s3api get-object --bucket "$bucket" --key routing/current --version-id "$id" "$out" >/dev/null
    pass "$n backup versions; newest $id from $(jq -r '.[] | select(.IsLatest) | .LastModified' <<<"$versions") saved to $out"
    ;;

  routing-verify)
    (($# == 2)) || fail "usage: routing-verify FILE"
    e=$(domain edge)
    out=$(edgectl restore -edge "$e" -operator-key "$OPERATOR_KEY_FILE" -backup "$2")
    echo "$out" | tee "$STATE/drill-$(stamp)-routing-verify.json"
    jq -e '.written == false' >/dev/null <<<"$out" || fail "a verify wrote something"
    pass "backup verified against boot $(jq -r .boot_id <<<"$out"); nothing written"
    ;;

  routing-refuse)
    (($# == 2)) || fail "usage: routing-refuse FILE"
    e=$(domain edge)
    [ "$(edge_state "$e")" = serving ] || fail "the edge isn't serving, so this proves nothing"
    if edgectl restore -edge "$e" -operator-key "$OPERATOR_KEY_FILE" -backup "$2" -write 2>"$STATE/refuse.err"; then
      fail "the serving edge took a write without -replace"
    fi
    cat "$STATE/refuse.err"
    [ "$(edge_state "$e")" = serving ] || fail "the refused write changed the edge's state"
    pass "the serving edge refused a write without -replace and kept serving"
    ;;

  routing-write)
    (($# == 2)) || fail "usage: routing-write FILE (the newest backup, from routing-fetch)"
    e=$(domain edge)
    [ "$(edge_state "$e")" = serving ] || fail "the edge isn't serving"
    for v in vault-a vault-b; do healthy "$(domain "$v")"; done
    pass "both vaults are up, so the restarted edge can pull its keys"
    newest=$(aws --profile "$AWS_PROFILE" s3api list-object-versions --bucket "$(backup_bucket)" --prefix routing/current \
      --query 'Versions[?IsLatest].VersionId' --output text)
    [ "$(basename "$2")" = "routing-$newest" ] ||
      fail "$2 isn't the newest backup ($newest); an older one undoes changes, so it isn't drilled on the live edge"
    confirm "Drain the live edge, install $2 with no skip, and restart it?"
    out=$(edgectl restore -edge "$e" -operator-key "$OPERATOR_KEY_FILE" -backup "$2" -write -replace)
    echo "$out" | tee "$STATE/drill-$(stamp)-routing-write.json"
    jq -e '.written and .restarting' >/dev/null <<<"$out" || fail "want written and restarting"
    wait_for_edge "$e" serving 900 || fail "the edge is $(edge_state "$e"), not serving, after the restore"
    pass "the edge restarted on the restored object and is serving; ready: $(curl -sS --max-time 60 "https://$e/ready")"
    ;;

  *)
    sed -n '2,13p' "$0"
    exit 2
    ;;
esac
