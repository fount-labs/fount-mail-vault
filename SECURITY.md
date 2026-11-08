# Security

## Reporting a vulnerability

Report it privately, never in a public issue:

- **GitHub:** the **Report a vulnerability** button on this repo's Security tab.
- **Email:** support@fount.sh, with "security" in the subject, if the button isn't there.

Say what you found, how to reproduce it, and what it lets an attacker do. We'll acknowledge it
within 7 days, keep you updated while we fix it, and credit you when it's disclosed unless you'd
rather we didn't. Please give us a reasonable chance to fix it before you publish.

## What's in scope

- The vault's code in this repo: the keyset, the transfer and restore protocol, recovery, and
  `vaultctl`.
- The release path: the reproducible build, the workflows, and `scripts/verify-release.sh`.
- Any claim in this repo's docs that the code doesn't back up. A false privacy claim is a bug.

The mail edge that the vault hands keys to is in
[`fount-mail-edge`](https://github.com/fount-labs/fount-mail-edge), with its own policy.

## Testing against the live vaults

Reading `/status`, the attestation, and published releases is fine. Don't submit recovery
shares or operator requests, read or change anyone else's data, or degrade the service for other
users. Good-faith research on those terms is welcome, and Fount's
[Terms](https://fount.sh/terms) say we won't pursue a claim over it.
