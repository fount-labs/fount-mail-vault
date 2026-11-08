# Making the operator and recovery keys

Do this once, before the first vault release. Only the public halves go into
`tinfoil-config.yml`, and nobody but the holder sees a private one.

| Key | Made with | Lives | Used for |
|---|---|---|---|
| Recovery identity, one per shareholder | `vaultctl recovery-keygen` | Offline only, never on a networked disk | Restoring the keyset after both vaults die |
| Operator key | `vaultctl operator-keygen` | The operator's laptop, with a copy offline | `vaultctl import-s3` and every `edgectl` request |

The operator key has to be online, because it signs requests to running enclaves. A
stolen one can overwrite the S3 credentials, add a role mailbox, or restore an old
routing backup. It can't read a key or a message. A recovery identity is the reverse:
it's used almost never, and enough of them rebuild the whole keyset, so it stays
offline.

## You need

- This repo, on the networked laptop.
- Two USB drives, labelled A and B. They hold the identities at launch, when the
  threshold is 1 of 2.
- An offline machine for step 2. A spare laptop with networking off is best. If you only
  have the one laptop, turn Wi-Fi off and write straight to the drives, never to its
  internal disk.

## 1. Build vaultctl for the offline machine

On the networked laptop:

```sh
GOOS=darwin GOARCH=arm64 go build -trimpath -o /Volumes/A/vaultctl ./cmd/vaultctl
shasum -a 256 /Volumes/A/vaultctl
```

Set `GOOS` and `GOARCH` for the offline machine. Note the hash, so step 2 can check
nothing changed it on the way.

## 2. Make the recovery identities, offline

On the offline machine, with drive A mounted:

```sh
shasum -a 256 /Volumes/A/vaultctl   # the same hash as step 1
/Volumes/A/vaultctl recovery-keygen -out /Volumes/A/recovery-a.txt
```

Swap to drive B, copying the binary over first, and repeat with `-out
/Volumes/B/recovery-b.txt`. Each command prints a `RECOVERY_RECIPIENT: age1…` line.
That's public, so write both down.

Then eject both drives and store them in different places, such as home and a safe
deposit box. Losing both identities, and then both vaults, loses every mailbox ID for good.

## 3. Make the operator key

On the networked laptop:

```sh
mkdir -p -m 700 ~/.fount
go run ./cmd/vaultctl operator-keygen -out ~/.fount/operator.key
```

It prints an `OPERATOR_KEY: <hex>` line, which is public. Copy `~/.fount/operator.key`
onto drive A as well, as the offline backup.

## 4. Hand over the public halves

These three values go into the configs, and they're safe to paste anywhere:

- both `age1…` recipients, as `RECOVERY_RECIPIENTS` in this repo's `tinfoil-config.yml`,
  comma-separated, with `RECOVERY_THRESHOLD: "1"`;
- the operator hex, as `OPERATOR_KEY` in this repo's config and in the edge's.

## Later: an outside custodian

To stop a malicious Fount, not just stolen credentials, the custodian runs step 2 on
their own machine and sends only their recipient. Then set the threshold to 2, release,
and fetch a new bundle. An old bundle still opens with one old identity,
so destroy the old bundles and identities.
