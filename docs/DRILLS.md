# Drills

Each drill shows that one recovery path works on the live enclaves, before real mail depends
on it. `scripts/drill.sh` runs each step and checks it, and asks before anything that changes
a container. Only the owner runs these. Results go in "The live run" in
`fount/docs/features/fount-fleet/fount-mail-vault.md`.

Run them in this order. Each one leans on the one before it.

| Drill | Shows | Needs |
|---|---|---|
| 1. Bundle check | Every stored bundle copy, plus one drive, rebuilds the keyset | The drives, an offline laptop |
| 2. Restart | A vault that loses its memory gets the same keyset back from its peer | Both vaults healthy, a fresh witness |
| 3. Recovery | An empty vault rebuilds the keyset from shares, live | A drill repo and release, a spare container, `vaultctl submit-share -offline-first` |
| 4. Routing restore | The edge's `routing/current` comes back from the backup bucket | A first routing backup. The edge's `docs/RESTORE.md` covers it |

## Before any drill

```sh
scripts/drill.sh preflight
```

Preflight checks that both vaults hold the committed keyset on `v0.1.2` with a clean self
check, that each witness has more than two days left, and that no container has saved
deploy-time variables. It also counts running containers against Tier 1's five.

**Don't drill on a stale witness.** A vault that boots after its release's witness has lapsed
can't verify itself, and its peer can't verify it, so a restart then turns into a full
recovery. Both witnesses expire 2026-11-13 22:01 UTC unless Tinfoil renews the latest release.

**Deploy-time variables.** `tinfoil container create` and `deploy` take `--variable KEY=VALUE`.
Tinfoil's docs say those fill bare-name `env` entries and don't replace measured values. Every
vault and edge entry is a literal, so nothing should take a variable. The docs don't say which
wins when the names match, so preflight refuses any container whose saved map isn't empty.
The drills never pass `--variable`. Open: ask Tinfoil, or probe it with a throwaway repo, never
with a vault.

## 1. Bundle check, offline

This shows that every copy of `keyset.bundle.json` is intact and opens with one drive. It never
touches an enclave.

1. On the networked laptop, build the tool: `go build -trimpath -o vaultctl ./cmd/vaultctl`.
   Copy each stored bundle to a different file name in the repo directory. The bundle is
   encrypted and gitignored.
2. Turn Wi-Fi off and unplug Ethernet. Then mount drive A.
3. For each copy, run `scripts/drill.sh bundle-check COPY /Volumes/A/recovery-a.txt`. It
   refuses while there's a default route, or if the identity isn't on a removable drive.
4. Eject drive A. Repeat with drive B, then with the paper copy of A typed onto a drive.
5. Turn the network back on.

Pass: every copy prints `rebuilds db2d1d4e…` with every identity. Record each copy's hash
prefix and where it's kept.

The live run's check proved only the copy it had just fetched. This drill proves the copies
you'd actually reach for. Do it before drill 2, because while one vault is down the bundle is
the only other copy.

## 2. Restart

```sh
scripts/drill.sh restart vault-b
scripts/drill.sh restart vault-a   # only after vault-b passed
```

For each vault, the script:

1. Checks that the *other* vault is healthy, then saves this vault's `/status`.
2. Asks, then runs `tinfoil container stop`, and waits until the host stops answering. A
   stopped container's domain stops resolving.
3. Runs `tinfoil container deploy` with the saved config, which is the same tag and no
   variables.
4. Waits up to 15 minutes, then checks the following:

| Check | Why |
|---|---|
| `keyset_commitment` is `db2d1d4e…` | The same keyset came back |
| `source` is `pulled from https://<other vault>` | It came from the peer, not from anything else |
| `transfer_key_fp` changed | It really rebooted, and the keyset was sealed to a new key |
| The other vault's `last_peer` is `vault`, the new fingerprint, `v0.1.2` | The holder verified this boot before it sealed |
| `has_s3` | The S3 credentials travel with the keyset |

vault-a lists itself first in `VAULT_PEERS`, so its restart logs one failed pull from itself
before it pulls from vault-b. That's expected.

**Abort.** If the vault doesn't come back, the other one still holds the keyset. Don't touch it.
Read the stuck vault's `/status` `refusals` and the other's. With both down, go to the README's
"Full recovery".

**Leave the edge alone during this drill.** Its egress allowlist names both vaults, and a stopped
vault's name doesn't resolve, so an edge that redeploys while a vault is stopped may not come up.
A running edge isn't affected. Don't run drill 4 at the same time.

If `MailWatchStack` is deployed, it emails about the down vault. That's expected, and it's a
check on the watch.

## 3. Recovery

This shows a vault with no peers rebuilding the committed keyset from one share. It's the real
keyset, because only that proves the stored bundle restores in an enclave. So the drill vault
is built to give that keyset to nobody.

### Why a separate repo

A drill vault from this repo would pull from vault-a straight away, because `VAULT_PEERS` is
measured, and then shares are refused with `errHeld`. So it needs its own config. Releasing that
config here as `v0.1.3` would be worse:

- The release workflow marks every release latest. If Tinfoil renews only the latest
  release's witness, `v0.1.2`, which both vaults run, would stop renewing.
- It would be a vault release that vault-a and vault-b would hand the keyset to. It would also
  raise the floor for every later vault.

So the drill uses `fount-labs/fount-mail-vault-drill`: the same image digest, with a config that
differs only in these values:

| Variable | Drill value | Effect |
|---|---|---|
| `VAULT_REPO` | `fount-labs/fount-mail-vault-drill` | vault-a and vault-b never verify it as a peer, and it only hands keys to drill releases |
| `EDGE_REPO` | `fount-labs/fount-mail-vault-drill-no-edge`, a repo that must never exist | No edge can pull from it |
| `VAULT_PEERS` | `vault-drill.fount.containers.tinfoil.dev` only | It doesn't restore from anyone, since pulling from itself just fails |
| `KEYSET_COMMITMENT` | `db2d1d4e…` | It accepts shares, and only the real keyset installs |
| `RECOVERY_*`, `OPERATOR_KEY` | Same as production | The real bundle's shares apply |

Put it under `fount-labs`, behind the same admin-only tag ruleset, so drill releases need the
same rights as production ones. A personal repo would leave the keyset behind weaker release
controls for as long as the drill vault lives.

### The identity is read offline

Plain `vaultctl submit-share` decrypts the share and sends it in one run, so the network has to
be up while the drive is mounted. That breaks the rule in `docs/KEYS.md`. `-offline-first`
splits the run in two:

1. With the network off, it reads the bundle and the identity and decrypts every share the
   identity opens. A wrong identity or a bad bundle fails here, before any prompt.
2. It prints `opened N share(s); nothing has been sent yet`, then
   `Eject the drive and turn the network on, then press Enter: `, and waits for a line on
   stdin. EOF or Ctrl-C ends it with nothing sent.
3. Only after Enter does it run `/operator/begin`, verify the attestation against `-repo` and
   `-tag`, seal, and send. Its three-minute timeout starts at Enter, not at launch.

The share stays in memory, is never written to disk, and its buffer is zeroed once it's sent
or the run fails. An offline seal doesn't fit instead, because the `/operator/begin` nonce
lasts two minutes.

`-offline-first` doesn't check that the network is really off. Check that yourself before you
mount the drive. The parsed identity is held by the age library, which gives no way to zero
it, so it stays in memory until vaultctl exits, which it does as soon as the share is sent.

At threshold 1 the share is the whole keyset, so it's still in memory while the laptop is
online. What the flag protects is the identity, which opens every future bundle made for
the same recipients.

### Steps

Owner actions, in order:

1. Create `fount-labs/fount-mail-vault-drill` with the tag ruleset. Copy this repo's
   `tinfoil-config.yml` with the changes above, and the release workflow. Release `v0.0.1`.
2. Check that a slot is free with `scripts/drill.sh preflight`, which should show 4 or fewer.
   Then:
   `tinfoil container create vault-drill --repo fount-labs/fount-mail-vault-drill --tag v0.0.1`.
3. Wait for `/status` on the drill vault to show `release_tag` `v0.0.1`, `has_keyset` false, and
   an empty `self_check_error`.
4. With Wi-Fi off and drive A mounted, run:
   `vaultctl submit-share -offline-first -vault vault-drill.fount.containers.tinfoil.dev -repo fount-labs/fount-mail-vault-drill -tag v0.0.1 -bundle keyset.bundle.json -identity /Volumes/A/recovery-a.txt`.
   It should print `opened 1 share(s); nothing has been sent yet` and the prompt. Eject the
   drive, turn the network on, and press Enter. It should then print
   `verified fount-labs/fount-mail-vault-drill v0.0.1, transfer key …` and
   `the vault restored the keyset`. Nothing is timed until Enter, so take as long as you need
   at the prompt.
5. `scripts/drill.sh recovery-status vault-drill.fount.containers.tinfoil.dev`. Pass: the
   committed keyset, source `restored from recovery shares`, `has_s3` false, since S3 isn't in
   the bundle, and no refusals.
6. Straight away: `tinfoil container stop vault-drill`, then
   `tinfoil container delete vault-drill`. Then archive the drill repo.

This drill doesn't cover "junk shares don't stop it". Only the unit tests do, since no tool
makes a junk share that opens with a real identity.

## 4. Routing restore

The edge's `docs/RESTORE.md` ("Drill") has the plan. `scripts/drill.sh` has its steps:
`routing-fetch`, `routing-verify`, `routing-refuse`, and `routing-write`.
