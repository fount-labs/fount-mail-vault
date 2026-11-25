# Coordinator generations and the rollback counter

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
  authenticated by the key its certificate names. A swap is on both vaults
  before it's answered.

Both are built: `wire/generation.go`, `wire/counter.go`, the boot in
`wire/protocol.go` (`PullBoot`), and in the vault `internal/vault/register.go`
and `counter.go`. The tests are `internal/vault/coordinator_test.go`, two
vaults with a router that takes either down, restarts it or promotes a
candidate.

## Why it isn't a small addition

1. **The Cloud vault is this code.** To it, the coordinator is an edge:
   `EDGE_REPO` is the coordinator's config repo. A coordinator release at or
   above `EDGE_MIN_TAG` gets the keyset and the S3 credentials in one sealed
   pull.
2. **The authority key can't come from the keyset.** The coordinator receives
   the whole keyset and derives its wrapping key from it. If the authority
   were derived from the keyset too, any coordinator could certify its own
   next generation. So it's a third secret, held by the vaults alone.
3. **The vault had no mutable state.** It held immutable secrets in memory.
   A counter that is on both vaults before a swap returns is a replicated
   register with compare-and-swap across two in-memory nodes.
4. **A generation needs the coordinator's key bound to its attestation.**
   Otherwise a party in the middle could swap the key in a boot request.

## Cloud mode

`COORDINATOR_MODE=1` turns it on. Without it, a vault refuses every call
below (409) and a boot (403), and a mail vault behaves exactly as before.
Cloud mode needs exactly two `VAULT_PEERS`, and `GENERATION_FLOOR` and
`COUNT_FLOOR` (decimal, below 2^63).

The Cloud pair's own `tinfoil-config.yml` (not this repo's root one, which is
the mail pair's; it's kept here as `cloud/tinfoil-config.yml`, for the
`fount-labs/fount-cloud-vault` repo to release from its root) sets, beyond
the mail vault's values:

```yaml
- EDGE_REPO: "<the coordinator's config repo>"
- EDGE_MIN_TAG: "<the oldest coordinator release allowed>"
- COORDINATOR_MODE: "1"
- GENERATION_AUTHORITY_KEY: "<base64 public key>" # empty only in the generating release
- GENERATION_FLOOR: "0"
- COUNT_FLOOR: "0"
- COORDINATOR_HOSTS: "<prod coordinator hostname>" # required with GENERATION_AUTHORITY_KEY
```

and adds to the shim's paths `/generate-generation`, `/coordinator/counter`,
`/register/head` and `/register/apply`. A vault calls both `VAULT_PEERS`
hostnames, its own included, through the shim.

## The generation keyset (vault-only)

- **What it holds:** one Ed25519 seed, the authority. Serialized as version
  byte `1` then the 32-byte seed.
- **Commitment:** the authority's public key, standard base64 with padding,
  as `GENERATION_AUTHORITY_KEY`. *This differs from the first draft, which
  used a hash.* A public key commits to its seed just as well, and this way
  the vault's `GENERATION_AUTHORITY_KEY`, the edge's
  `COORDINATOR_AUTHORITY_KEY` and the coordinator's
  `--coordinator-authority-key` are one string, which a reviewer compares by
  eye.
- **How it's made:** `POST /generate-generation`, once, in a Cloud release
  with a `KEYSET_COMMITMENT`, no `GENERATION_AUTHORITY_KEY`, holding the
  keyset. It answers the public key. The register starts there, at
  `(GENERATION_FLOOR, COUNT_FLOOR)` and no key.
- **Who gets it:** vaults only, in the keyset's sealed pull
  (`Payload.GenerationKeyset`, with the register in `Payload.Register`).
  An `EDGE_REPO` requester (the coordinator) never gets it or the register.
  A release with `GENERATION_AUTHORITY_KEY` isn't "holding" until it has the
  matching generation keyset, so it keeps pulling.
- **No recovery shares.** If both vaults die, both the generation keyset and
  the register are gone. See "Both vaults lost".

## Booting a generation

The boot rides the existing pull (`wire.PullBoot`):

1. The coordinator draws a per-boot Ed25519 key, gets the holder's one-use
   nonce and transfer key (`holder_key`) from `/transfer/begin`, and attests
   to `sha256("fount-coordinator-boot/v1\x00" ‖ issued nonce ‖ coordinator_key)`
   instead of the nonce.
2. It sends `coordinator_key` and `boot_proof` on `/transfer/finish`.
3. The vault verifies the document against that derived nonce, so the
   document vouches for the key. It refuses a `coordinator_key` from a vault,
   or in a vault without Cloud mode.
4. **Proof of possession.** It checks `boot_proof` (below). A document only
   says which transfer key is attested: the shim serves a genuine
   coordinator's document for any nonce to anyone, so without the proof
   anyone could attest the prod coordinator to their own per-boot key and
   take a generation (security review 2026-11-24, C1).
5. **The coordinator's host.** It checks that the document's attested TLS
   key (`crypto_material` id `tls`) is the key one of `COORDINATOR_HOSTS`
   serves now, over a TLS handshake whose chain verified for that hostname.
   A copy of the public release deployed in another Tinfoil account is
   genuine and holds its own keys, but serves another hostname with another
   TLS key, so it can't boot (vault review H2, broker review H3).
6. **Rate.** Each vault allows 4 boots at once and one more every 10
   minutes. A boot refused before it reached either vault (one vault down)
   is given back. A refused boot is `429 refused at boot rate`; the broker
   retries with its backoff.
7. The vault proposes the next register state: generation + 1, this key, the
   count kept (see "Replication"). Only once both vaults hold it does the
   vault sign the certificate and put it in the sealed payload as
   `generation_certificate`, next to the keyset and the S3 credentials.
8. The coordinator checks the certificate against its own measured authority
   key, and that it names its key.

`boot_proof` is `HMAC-SHA256(K, "fount-coordinator-boot/v1\x00" ‖
requester transfer key ‖ holder transfer key ‖ issued nonce ‖ answer nonce ‖
coordinator_key)`, where `K = HKDF-SHA256(X25519(mine, peer), info =
"fount-mail-vault/v1/boot-proof\x00")`. The coordinator computes it with its
transfer key and `holder_key`; the vault with its own and the key the
document endorses. Only the two attested keys can compute `K`, and the HKDF
label keeps it apart from the boxes' keys from the same agreement.
`holder_key` is unauthenticated: a wrong one only makes a proof the vault
refuses. Someone in the middle can relay a real coordinator's proof, which
boots a generation for the real coordinator's key, as the real boot would;
it can't change the key, the nonces or the vault the proof is for. A
`wire.PullBoot` against a vault that names no `holder_key` sends no proof,
so a new coordinator still boots at an old vault; a new vault refuses a boot
without one.

A pull without `coordinator_key` is the plain keyset pull and moves nothing.
The broker's restore dry run uses it. A retry after a lost answer moves the
generation again. That's harmless: the first one was never used.

The certificate is the edge's format exactly (`wire_test` pins a vector
produced by the edge's own `generation.Sign`):
`b64url(json{"generation","coordinator_key","issued_at"}) "." b64url(sig)`,
with the signature over `"fount-coordinator-generation/v1\n" ‖ json`.

## The counter

`POST /coordinator/counter`, through the shim. Bodies are JSON, at most 4 KiB.
At most 16 swaps run at once (more get 429). Loads are unauthenticated, so
they don't take those slots: they share settles, at most two at a time, each
starting after the loads it answers arrived.

A cas moves the count by at most 2^20 and to at most 2^63−1 (`wire.MaxCount`,
`wire.MaxCountStep`): one swap to 2^64−1 left no successor, and a count at
2^63 or more couldn't be written back as `COUNT_FLOOR` (review M4).

| Op | Request | Notes |
|---|---|---|
| `load` | `{op, nonce}` | Unauthenticated: a dry run has no generation |
| `cas` | `{op, nonce, generation, prev, next, signature}` | `signature` is Ed25519 by the current generation's key over `"fount-coordinator-counter/v1/cas\x00" ‖ nonce ‖ be64(generation) ‖ be64(prev) ‖ be64(next)` |

`nonce` is 32 fresh random bytes, hex. The answer is
`{result, generation, count, signature}`. The signature is the authority's
over `"fount-coordinator-counter/v1/answer\x00" ‖ digest ‖ result ‖ 0x00 ‖
be64(generation) ‖ be64(count)`. `digest` is
`sha256("fount-coordinator-counter/v1/request\x00" ‖ op ‖ 0x00 ‖ nonce ‖
be64(generation) ‖ be64(prev) ‖ be64(next))`. So an answer is bound to one
request: a replayed or forged answer, success or refusal, doesn't verify.

| Result | HTTP | Broker error |
|---|---|---|
| `ok` | 200 | |
| `stale_generation`: another generation is current | 409 | `ErrVaultGeneration` |
| `bad_signature`: the generation is current, the key isn't its | 409 | `ErrVaultGeneration` |
| `no_generation`: nothing has booted since the register began | 409 | `ErrVaultGeneration` |
| `count_mismatch`: the count isn't `prev`, or `next ≤ prev` | 409 | `ErrVaultCount` |
| anything unsigned (503 when the register can't be read or changed, 429, a network error) | | unavailable: retry |

The checks run in that order, against the head both vaults hold. A cas that
meets `count == next` where the last state was made by this very
`(generation, prev, next)` answers `ok`, so a retry after a lost answer is
idempotent. Only the last swap is answered again. The broker also takes a
count ahead of its own, within its own generation, as its lost answer
(`backupcommit.go`). The wire client (`wire.CounterClient`) tries each vault
in order until one gives a signed answer, and checks that an `ok` cas names
its generation and `next`.

### Version 2: the count counts a state

A version 1 count says how many security changes there were, not which, so
a fenced generation's disk or backup root at `seq == count` passed (broker
review H2). A version 2 request has `"v": 2`:

- a cas carries `state_digest`, hex of 32 bytes, the digest of the
  coordinator state its `next` counts, and signs it:
  `"fount-coordinator-counter/v2/cas\x00" ‖ nonce ‖ be64(generation) ‖
  be64(prev) ‖ be64(next) ‖ digest`;
- the register keeps the digest with the generation whose cas set it
  (`writer`), and a boot keeps both;
- the answer carries `state_digest` and `writer`, signed:
  `"fount-coordinator-counter/v2/answer\x00" ‖ request digest ‖ result ‖
  0x00 ‖ be64(generation) ‖ be64(count) ‖ len ‖ digest ‖ be64(writer)`, where
  the request digest appends `0x02 ‖ len ‖ digest` at version 2;
- a retry of the last swap must name the same digest.

Version 1 requests are answered exactly as before, and register states no
version 2 cas made hash as before, so mixed vault releases agree until a
coordinator sends version 2. `wire.CounterClient.LoadState` and
`CompareAndSwapState` speak it. What the digest covers, and what the
coordinator does when its disk or a root doesn't match, is fount-broker's.

## Replication

*This differs from the first draft, which had the first vault forward every
call to the second as a single serializer.* With two in-memory nodes and no
leases, a serializer needs to know it's the serializer. A vault can't tell
reliably that it's the one at `VAULT_PEERS[0]`: an upgrade candidate is the
same release on another hostname. And a lease that expires can fork. So the
register is a hash chain, and the order of the two vaults does the
serializing.

**The register.** A state is `{version, prev, generation, key, count, swap}`.
`prev` is the hex SHA-256 of the state before, over a fixed binary encoding
(`register.go`, `hash`). Version 0 is the genesis, with no predecessor.
A state follows another only as a boot (generation + 1, a 32-byte key, the
count kept, no swap) or a swap (the same generation and key, count up, and
`swap` naming the cas). Each vault keeps its last 64 states.

**Taking a state.** A vault takes a chain only if it extends the head it
holds: it starts from the head, or links to it. So it takes at most one
successor of any state. A chain whose tip it already holds is accepted again
(a repeated delivery). Anything else is rejected, and nothing changes.

**A change.** Whichever vault handles a call (a boot, a load, a cas):

1. Reads both hosts' heads: `https://VAULT_PEERS[0]` and `[1]`, at
   `/register/head`. Both must answer, from two different instances. Each
   process draws an instance ID, so one vault answering for both hostnames is
   refused.
2. Settles them:
   - Equal, it goes on.
   - One behind and in the other's history (a change cut short, a restart, a
     promoted candidate), it pushes the missing states to the one behind.
   - Two different states at one version, or a gap wider than the history:
     **diverged**, refused until an operator restarts one vault.
3. Decides the next state from the settled head, if any. A load stops here.
4. Applies `[head, next]` to `VAULT_PEERS[0]`, then, only if that vault
   accepted, to `VAULT_PEERS[1]`. Each must accept, from the instance it read.
5. Answers only then. Within one process a mutex runs changes one at a time.

Two changes racing from different vaults both try `VAULT_PEERS[0]` first, so
at most one wins there. The loser stops before `VAULT_PEERS[1]`. The winner's
change can't be refused at `VAULT_PEERS[1]` by the loser, which never got
there. A change cut short, accepted by `VAULT_PEERS[0]` and not
`VAULT_PEERS[1]`, was never answered, and the next settle finishes it: a lost
answer, which the coordinator already handles.

**Peer authentication.** `/register/head` and `/register/apply` take
`{body, mac}`. The MAC is HMAC-SHA256 under
`HKDF-SHA256(seed, info "fount-coordinator-register/peer/v1")` over the path
and the body. The answer's MAC also covers the SHA-256 of the request body.
Only a vault holding the generation keyset can make or answer one. Nothing on
this path is secret, so nothing is sealed. TLS through the shim keeps it from
the network. The MAC keeps out everyone else who can reach the shim.

**Syncing.** Every 15 s a Cloud vault settles both hosts, and brings its own
copy up. So a held upgrade candidate tracks production. Its last sync shows
on `/status` under `coordinator.last_sync`, with the register's version, head
hash, generation and count.

**Pulled registers.** A vault takes a register only with the generation
keyset, only from a vault, and only at or above its release's floors.

### When a vault is down or mid-upgrade

Every call needs both vaults, loads included. Otherwise a vault restored from
a stale peer could answer a lower count, which would let a rolled-back volume
boot. While either vault is down, boots, loads and swaps answer an unsigned
503. The coordinator waits for a vault at boot, and the broker retries a
security change (`ErrNotDurable`). Backups go on, and only their counting
waits.

- **A restart.** The restarted vault pulls the keyset, the generation keyset
  and the register from its peer. The next call or sync settles both.
- **An upgrade** (`--hold=true`, then promote). The candidate pulls from a
  production vault, then follows both by sync while held. A call it handles
  reads both production vaults, like any vault. On promote, the next settle
  brings it up if anything changed since its last sync.
- **A rollback window, and the rule that closes it.** Suppose a candidate
  promoted with a stale register replaced one vault, and *then* the other
  vault restarted before any settle. The restarted vault would pull the stale
  register, and changes made in that gap would be lost. So, for each vault in
  turn:
  1. Promote it.
  2. Wait until both vaults' `/status` show the same `coordinator.register`
     head.
  3. Only then touch the other vault.

  The same rule applies to restarting a vault by hand.
- **Diverged.** This shouldn't happen. It would take someone replaying a
  captured `/register/apply` inside TLS, or both vaults taking different
  states some other way. It is refused until one vault is restarted, which
  then pulls the other's register. Pick the vault whose `/status` shows the
  higher count. A change on the other branch was never answered.

A third vault would allow majority quorums. A compare-and-swap across a
majority needs consensus, though, so that's out of scope for launch.

### Both vaults lost

The register and the generation keyset are gone, as the keyset would be.
Full recovery already needs the shareholders:

1. Restore the keyset from shares as usual.
2. Run a generating release (`GENERATION_AUTHORITY_KEY` empty), with
   `GENERATION_FLOOR` at least the edge's highest generation, and
   `COUNT_FLOOR` at least the newest backup's security sequence.
3. Release the pair with the new authority key and the same floors.
4. Release the edge and the coordinator's config with the new key.

The floors are public, so the event can be audited. Whoever sets them could
pick a lower count, so after a total loss, rollback protection rests on the
operator. That residual risk is stated publicly. A floor above the register
a peer offers makes a release refuse that register, so a raised floor can't
be undone by a peer.

A checkpoint of the register in S3, MACed under a vault-only key, wouldn't
close the gap: whoever holds the bucket can replay an older version.

## What each party holds

| Party | Holds |
|---|---|
| Each Cloud vault (in memory) | The keyset, the S3 credentials, the generation keyset (authority seed), the register's last 64 states |
| The coordinator (in memory) | The keyset (its wrapping key), the S3 credentials, its per-boot key and certificate |
| Measured release configs (public) | The keyset commitment, the authority public key (vault, edge, coordinator), the floors |
| The edge | The authority public key, and the highest generation it has seen |

## Nonces

`/transfer/begin` and `/operator/begin` are unauthenticated, and used to
share one pool of 256 open nonces, so anyone could stop every restore, boot
and import (review H1). Now a nonce is `use (1) ‖ expiry, Unix ms (8) ‖
random (7) ‖ HMAC (16)` under a per-process key: issuing keeps nothing. A
nonce is spent only once its exchange proved itself, into a set per class:

| Class | Spent after | When full |
|---|---|---|
| pull | the document verifies | evicts its oldest: a pull has no side effect, and its box opens only with the attested key |
| boot | the boot proof verifies | refuses (boots are rate-limited, so it never fills) |
| share | the share box opens | refuses |
| import | the operator's signature verifies and the box opens | refuses |

A nonce from a vault that restarted since is unknown; the caller begins
again.

## Monitoring

`/status` → `coordinator`:

- `boots`: `count`, `rate_limited`, `wrong_host`, `allowance`, and the last
  boot's `last_at`, `last_generation`, `last_repo`, `last_tag`,
  `last_chip_id`, `last_transfer_key_fp`, `last_tls_key_fp`. Alert on every
  change of `count` or `register.generation` that isn't a deploy you made,
  on any `wrong_host` or `rate_limited`, and when the two vaults'
  `register` heads differ for more than a minute.
- `coordinator_hosts`: the hostnames a boot must come from.

`/status` is unauthenticated and its `last_peer` and `refusals` can be set by
anyone replaying public documents (review L3), so treat it as a signal, not
proof.

## Runbook: who may boot, and retiring releases

- `COORDINATOR_HOSTS` is required with `GENERATION_AUTHORITY_KEY`. Set it to
  the prod coordinator's hostname(s) exactly. Before a release with it, check
  live that the coordinator's attestation document lists a `tls` key in
  `crypto_material` and that `openssl s_client -connect <host>:443` shows a
  leaf whose SPKI SHA-256 matches; if the document has no `tls` key, every
  boot fails closed with `endorses no TLS key`.
- A boot needs the hostname to route to the booting enclave. During a
  coordinator update the old instance may still answer for a moment; the
  boot is refused `refused at coordinator host` and the coordinator's
  backoff retries.
- **Raise `EDGE_MIN_TAG` past every restore release.** A coordinator
  release cut with `--restore latest`, `--restore roots/…` or
  `--restore-dry-run` in its measured args stays deployable by anyone for as
  long as its tag is ≥ `EDGE_MIN_TAG`. The host pin stops such a copy
  booting, but it still gets the keyset and the S3 credentials by a plain
  pull, and on Fount's own host it would restore again. So: cut restore
  releases only while a restore is in progress; afterwards release the
  Cloud vault with `EDGE_MIN_TAG` above every restore and restore-dry-run
  tag, and above every coordinator tag that predates the boot proof. Never
  tag a restore release at or above the live minimum except during a
  restore.
- After a drill or a restore, confirm on both vaults' `/status` that
  `edge_min_tag` is the new floor and `boots.count` moved only for the boots
  you made.
- A boot at a vault that's at its rate limit waits up to 10 minutes. Don't
  restart a vault to reset it: a vault restart during a flood or an outage
  is what loses the generation keyset.

## Ship order (2026-11-24 fixes)

1. Merge this repo's wire changes. The broker bumps
   `github.com/fount-labs/fount-mail-vault/wire` and releases a coordinator
   that sends the boot proof (it still boots at an old vault, which names
   no `holder_key`).
2. Release the Cloud vault pair (both vaults, held then promoted) with the
   boot proof, `COORDINATOR_HOSTS`, and `EDGE_MIN_TAG` at that coordinator
   release, so older coordinators, which can't prove, and old restore
   releases are refused at the minimum tag.
3. Only then a coordinator release that uses counter version 2 (a vault
   before step 2 can't answer it, and a vault mid-upgrade would hash the
   digest differently).

## Broker side

- `vaultkey.Fetch` boots: it sends a fresh `coordinator_key` and keeps the
  certificate, the generation key and the S3 credentials.
- `vaultcounter` implements `coordinator.VaultCounter` with
  `wire.CounterClient`.
- `--wrapping-key vault` takes `--backup-bucket` once
  `--coordinator-authority-key` is set. It uses the bucket credentials from
  the vault (`vaultctl import-s3`), not the environment.

## Drills before launch

- Restart each vault in turn while the coordinator swaps.
- Upgrade each vault (hold, sync, promote, wait for equal heads) with a swap
  in flight.
- Kill one vault for a while: everything refuses, and nothing forks.
- Total loss with floors, on a scratch pair.
- The 2026-11-24 negatives: a boot with a public document and no proof; a
  copy of the coordinator release on another hostname; a begin and load
  flood during a vault restart; a fifth boot inside ten minutes.
