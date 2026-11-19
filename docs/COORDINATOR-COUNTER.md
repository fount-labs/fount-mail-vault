# Coordinator generations and the rollback counter (design, not built)

Fount Cloud's coordinator needs two things from its vault pair beyond the
wrapping key (fount `launch-plan.md` decisions 17 and 18; broker
`internal/coordinator/backupvault.go`):

- **A generation.** At every coordinator boot, the vault moves a number on and
  signs a certificate binding it to that boot's own Ed25519 key, in the format
  the mail edge checks against `COORDINATOR_AUTHORITY_KEY` (edge
  `docs/DESIGN.md`, "Generations"). Restores and upgrades both boot a
  coordinator, so either one fences the coordinator before it, at the edge and
  at the vault.
- **A counter.** One per deployment. `Load` answers `(generation, count)`.
  `CompareAndSwap(generation, prev, next)` succeeds only when the generation
  is current, the count is `prev`, and `next > prev`. Moving the generation
  keeps the count. Only the current generation's coordinator may swap,
  authenticated by the key its certificate names. A swap must be durable and
  on both vaults before it returns.

This note records why that isn't a small addition to this repo, and the shape
proposed for it. Until it's built, the broker refuses backups under the
vault's key. Dev and test coordinators use `--dev-vault`, a file
(`coordinator.FileVault`) that behaves like the design below on one machine.

## Why it's more than an endpoint

1. **The Cloud vault is this code, unchanged.** To it, the coordinator is an
   edge: `EDGE_REPO` is the coordinator's config repo. A coordinator release
   at or above `EDGE_MIN_TAG` gets the keyset and the S3 credentials in one
   sealed pull, and nothing else.
2. **The authority key can't come from the keyset.** The coordinator receives
   the whole keyset and derives its wrapping key from it (broker
   `internal/vaultkey`). If the authority key were derived from the keyset
   too, any coordinator could certify its own next generation, and the fence
   would mean nothing. The authority key must be held by the vaults alone.
3. **The vault has no mutable state.** It holds immutable secrets in memory,
   and a peer gets them in one pull. There's no disk, no write replication, no
   version, and nothing for the upgrade candidate (`--hold=true`, then promote)
   to catch up on after its pull. A counter that is durable and on both vaults
   before a swap returns is a replicated register with compare-and-swap,
   across two in-memory nodes.
4. **A generation needs the coordinator's key bound to its attestation.**
   Otherwise a party in the middle can swap the key in a boot request.

## Proposed design

### The generation keyset (vault-only)

A third secret, built like the send keyset (`docs/SEND-KEYS.md`):

- **What it holds:** an Ed25519 authority seed.
- **Commitment:** `sha256("fount-coordinator-generation-keyset/v1" ‖ bytes)`
  as `GENERATION_KEYSET_COMMITMENT`.
- **How it's made:** `POST /generate-generation`, in a release with a
  `KEYSET_COMMITMENT` and no `GENERATION_KEYSET_COMMITMENT`. It answers the
  commitment and the public key. That key becomes the edge's and the
  coordinator's `COORDINATOR_AUTHORITY_KEY`.
- **Who gets it:** it moves only vault to vault, in the keyset's pull. It's
  never sent to an `EDGE_REPO` requester, which here is the coordinator.
- **No recovery shares.** If both vaults die, generate a new one and release
  the edge with the new public key. A new config value,
  `GENERATION_FLOOR`, starts the numbering above the last generation the edge
  saw, because the edge refuses a lower one.

### Booting a generation

The boot rides the existing pull, so there is no new authentication:

- **The request.** A Cloud-mode vault (a new `COORDINATOR_MODE=1`) reads
  `coordinator_key` on `/transfer/finish` from an `EDGE_REPO` requester. The
  requester's attestation nonce becomes
  `sha256("fount-coordinator-boot/v1" ‖ issued nonce ‖ coordinator_key)`,
  so the document vouches for the key.
- **What the vault does.** It moves the register's generation on, keeps the
  count, records the key as the current one, and puts
  `generation_certificate` in the sealed payload, next to the keyset and the
  S3 credentials.
- **A retry after a lost answer** moves the generation again. That's harmless,
  because the first one was never used.

### The counter calls

`POST /coordinator/counter`, plain HTTPS through the shim:

| Call | Request | Vault answer |
|---|---|---|
| `load` | `{op, nonce}`, unauthenticated: a dry run with no generation must be able to read it | `{generation, count, nonce}` |
| `cas` | `{op, generation, prev, next, nonce}`, Ed25519-signed by the key the current certificate names (`Fount-Key-Id` and the label `fount-coordinator-counter/v1`, as on the edge's coordinator routes) | Success. Or 409 `stale_generation` (`ErrVaultGeneration`), or 409 `count_mismatch` with the count (`ErrVaultCount`) |

Every answer is signed by the authority key over the label, a hash of the
request, and the answer. The coordinator checks it with
`COORDINATOR_AUTHORITY_KEY` from its own measured config, so a network
attacker can't fake a success or replay an old count.

A `cas` that meets `count == next` with the same `(generation, prev)` as the
last applied swap answers success, so a retry after a lost answer is
idempotent. The broker also takes a count ahead of its own, within its own
generation, as its lost answer (broker `backupcommit.go`).

### Replication: read-all, write-all, one serializer

The register is `(version, generation, coordinator_key, count, last_swap)`.

- **Serializer.** The first vault in `VAULT_PEERS` is the primary. The other
  forwards every counter call and every boot to it.
- **Every call needs both vaults, reads included.** The primary applies a
  change only after the secondary has stored the new register at
  `version + 1` and acknowledged it, over the attested vault-to-vault pull
  channel, sealed as the keyset is. A `load` also asks the secondary and
  answers the higher version. Otherwise a just-promoted upgrade candidate
  could answer a stale, lower count, which would let a rolled-back volume
  boot.
- **Catch-up.** A vault that sees a peer's higher version, from a vault
  release that verifies, adopts it. Versions only move forward. Every
  committed change is on both vaults, so after one vault restarts or is
  upgraded, either vault plus the other's state gives the latest register.
  The restarted vault won't serve the counter until it has caught up.
- **Availability cost.** While either vault is down or mid-upgrade, boots,
  loads and swaps fail. The coordinator already waits for a vault at boot.
  A security change fails with `ErrNotDurable`, and the client retries.
  Backups go on, and only their counting waits. A third vault would allow
  majority quorums, but a compare-and-swap across a majority needs consensus
  (Paxos or Raft), not just quorum reads and writes. It's out of scope for
  launch.
- **Both vaults lost at once.** The register is gone, as the keyset would be.
  Full recovery already needs the shareholders. The new release sets
  `GENERATION_FLOOR` and `COUNT_FLOOR` in its measured, public config, from
  the edge's highest generation and the newest backup's security sequence.
  The floors are public, so the event can be audited. Whoever sets them could
  pick a lower count, so after a total loss, rollback protection rests on the
  operator. That is the residual risk to state publicly.

  A checkpoint of the register in S3, MACed under a vault-only key, wouldn't
  close this gap: whoever holds the bucket can replay an older version.

### Broker side, once this lands

- `vaultkey.Fetch` sends the boot's `coordinator_key`, and keeps
  `generation_certificate` and `S3` from the payload.
- A `vaultcounter` client implements `coordinator.VaultCounter` against
  `/coordinator/counter`, verifying the vault's signatures.
- `--wrapping-key vault` then takes `--backup-bucket`, using the bucket
  credentials from the vault (`vaultctl import-s3`) instead of the
  environment.

## Size

These parts are new in this repo:

- a third secret, with its commitment and its transfer rules;
- a Cloud mode;
- the boot exchange;
- a replicated register with catch-up, including the upgrade candidate;
- two signed endpoints;
- drills for a vault restart, an upgrade with a swap in flight, and total
  loss with floors.

It changes the deployed vault's security core, so it belongs in its own lane
and review, not as a counter endpoint added on the side.
