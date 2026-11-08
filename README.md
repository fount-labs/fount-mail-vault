# Fount Mail vault

Holds Fount Mail's keyset in enclave memory, on Tinfoil, and hands it only to verified vault and
edge releases. No person, AWS account, or disk ever holds the keys in plaintext. The design is in
`fount/docs/features/fount-fleet/fount-mail-vault.md`.

```text
vault-a <-> vault-b       restore each other; both verify
   |           |
   +--> edge <-+          the edge pulls; the vault verifies it
```

## What's here

| Path | What it is |
|---|---|
| `wire/` | A nested module, standard library only: the keyset, its commitment, the sealed box, and the pull protocol. The edge imports it |
| `internal/vault` | The server: generate, transfer with pins and minimum tags, restore from peers, recovery, and S3 import |
| `internal/shamir` | Shamir's scheme over GF(256), constant-time |
| `internal/recovery` | The recovery bundle: one age-encrypted share per recipient |
| `internal/opclient`, `cmd/vaultctl` | The operator's tool |

## Who gets the keyset

| Requester | Must verify as | Minimum tag |
|---|---|---|
| Vault | `VAULT_REPO` | This vault's own tag, from its own attestation |
| Edge | `EDGE_REPO` | `EDGE_MIN_TAG` |

An edge also needs the release to have a commitment. A vault that can't read its own tag refuses
every vault peer.

## Config

All of it is in `tinfoil-config.yml`, measured and public. The vault won't boot if a value is
missing or malformed.

| Variable | Meaning |
|---|---|
| `KEYSET_COMMITMENT` | Empty only in the release that generates. Every later release must set it |
| `EDGE_MIN_TAG` | Raise it to retire old edge releases |
| `VAULT_PEERS` | Both vault hostnames. Pulling from itself just fails |
| `RECOVERY_RECIPIENTS`, `RECOVERY_THRESHOLD` | age X25519 recipients, one share each, and how many shares restore |
| `OPERATOR_KEY` | Ed25519 public key that signs S3 credential imports |

## Bootstrap

Do this once. `scripts/live.sh` runs each step below and checks it before the next; it
creates Tinfoil containers but leaves every GitHub push and release to you.

1. Make the keys, following `docs/KEYS.md`: one recovery identity per shareholder, made
   offline with `vaultctl recovery-keygen`, and the operator key.
2. Fill in `RECOVERY_RECIPIENTS` and `OPERATOR_KEY`. Run *Build Image* and pin the digest it
   reports, then release `v0.1.0` with an empty commitment.
3. Deploy `vault-a` from `v0.1.0`, and run `curl -X POST https://vault-a.../generate`. It answers
   with the commitment.
4. Run `vaultctl bundle -vault vault-a... -out keyset.bundle.json`, then `vaultctl check-bundle`
   with enough identities to meet the threshold. Store copies of the bundle in several places.
5. Set `KEYSET_COMMITMENT` and release `v0.1.1`. Upgrade `vault-a` with
   `tinfoil container update vault-a --tag v0.1.1 --hold=true`. The candidate pulls from
   production by itself. Check its `/status` on port 4443, then promote.
6. Deploy `vault-b` from `v0.1.1`, and import the S3 credentials with `vaultctl import-s3`.
7. Release the edge with the same commitment and `OPERATOR_KEY`. Its first boot waits for
   `edgectl init`, then add `abuse@` and `postmaster@` with `edgectl provision`. The edge's
   `docs/BUILD.md` has the commands.

`v0.1.0` can never get the keys back, because every later release is above it.

## Repos and releases

This repo and `fount-labs/fount-mail-edge` are public, so anyone can rebuild a release and compare
it with what runs. A ruleset on each makes `v*` tags creatable only by org admins, and permanent
once pushed. Whoever can release can get the keys, so `docs/KEYS.md` lists the accounts that
need hardware keys.

To release: run *Build Image* from `main`, pin the digest it reports in `tinfoil-config.yml`,
commit, then `git tag vX.Y.Z && git push origin vX.Y.Z`. The tag push runs *Tinfoil Release*,
which checks the tag is on `main` and the config has no placeholders, then measures, publishes,
and marks the release latest so its witness renews. The pushed image is the output of
`scripts/build-image.sh`, which CI builds on two runners and requires to match.

## Routine work

- **Upgrading a vault.** Release, then update one vault with `--hold=true`, wait for the
  candidate's `has_keyset`, and promote. Then do the other.
- **Rolling back.** Roll forward instead: release the old code under a new tag. A lower tag would
  be refused.
- **Watching.** `/status` shows `freshness_expires_at`, from an hourly self-check, plus
  `refusals`, `chip_id`, and `same_chip_as_last_peer`. `fount-infra`'s `MailWatchStack` reads it
  every 15 minutes and emails on problems, and on every new release of either repo.

## Full recovery

If both vaults are gone:

1. Deploy a fresh vault from the latest release.
2. Each shareholder runs
   `vaultctl submit-share -vault HOST -tag vX.Y.Z -bundle keyset.bundle.json -identity ID`, on
   their own machine. It verifies the vault before sending anything.
3. Once the vault has enough shares that rebuild the committed keyset, it installs it. Junk shares
   don't stop it.
4. Import the S3 credentials again, then deploy the other vault, which pulls from the first.

## Testing

```bash
go test -race ./... && (cd wire && go test -race ./...)
```

The tests use a fake attestation authority. Only a live run on Tinfoil proves the attestation
parts.
