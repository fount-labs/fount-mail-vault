// Package vault holds the Fount Mail keyset in enclave memory and hands it only
// to verified vaults and edges.
package vault

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/fount-labs/fount-mail-vault/internal/recovery"
	"github.com/fount-labs/fount-mail-vault/wire"
)

// Config is measured with the release, so every field is public and changing one
// takes a new release.
type Config struct {
	VaultRepo  string // VAULT_REPO: vault peers must be releases of this repo
	EdgeRepo   string // EDGE_REPO: edges must be releases of this repo
	EdgeMinTag string // EDGE_MIN_TAG: the oldest edge release that gets keys
	Commitment string // KEYSET_COMMITMENT: empty only in the release that generates
	// SEND_KEYSET_COMMITMENT: empty only in a release that may generate the send
	// keyset, which must have a KEYSET_COMMITMENT.
	SendCommitment string
	Peers          []string // VAULT_PEERS: vault hostnames to restore from, which may include this one
	Recipients     []string // RECOVERY_RECIPIENTS: age X25519 recipients, one share each
	Threshold      int      // RECOVERY_THRESHOLD: shares needed to restore
	OperatorKey    ed25519.PublicKey
}

// LoadConfig fails on anything missing or malformed, because a vault that boots
// with a bad config could refuse every peer or, worse, accept the wrong one.
func LoadConfig(getenv func(string) string) (*Config, error) {
	c := &Config{
		VaultRepo:      getenv("VAULT_REPO"),
		EdgeRepo:       getenv("EDGE_REPO"),
		EdgeMinTag:     getenv("EDGE_MIN_TAG"),
		Commitment:     getenv("KEYSET_COMMITMENT"),
		SendCommitment: getenv("SEND_KEYSET_COMMITMENT"),
	}
	for name, repo := range map[string]string{"VAULT_REPO": c.VaultRepo, "EDGE_REPO": c.EdgeRepo} {
		if owner, name2, ok := strings.Cut(repo, "/"); !ok || owner == "" || name2 == "" || strings.ContainsAny(repo, "@ ") {
			return nil, fmt.Errorf("%s must be owner/repo with no tag, got %q", name, repo)
		}
	}
	if c.VaultRepo == c.EdgeRepo {
		return nil, fmt.Errorf("VAULT_REPO and EDGE_REPO are both %s", c.VaultRepo)
	}
	if !semver.IsValid(c.EdgeMinTag) {
		return nil, fmt.Errorf("EDGE_MIN_TAG %q isn't a version", c.EdgeMinTag)
	}
	if c.Commitment != "" {
		if err := wire.ValidateCommitment(c.Commitment); err != nil {
			return nil, fmt.Errorf("KEYSET_COMMITMENT: %w", err)
		}
	}
	if c.SendCommitment != "" {
		if c.Commitment == "" {
			return nil, fmt.Errorf("SEND_KEYSET_COMMITMENT is set but KEYSET_COMMITMENT isn't")
		}
		if err := wire.ValidateCommitment(c.SendCommitment); err != nil {
			return nil, fmt.Errorf("SEND_KEYSET_COMMITMENT: %w", err)
		}
		if c.SendCommitment == c.Commitment {
			return nil, fmt.Errorf("SEND_KEYSET_COMMITMENT is the KEYSET_COMMITMENT")
		}
	}
	for _, p := range strings.Split(getenv("VAULT_PEERS"), ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if strings.ContainsAny(p, "/?#@ ") {
			return nil, fmt.Errorf("VAULT_PEERS entry %q must be a bare hostname", p)
		}
		c.Peers = append(c.Peers, p)
	}
	if len(c.Peers) == 0 {
		return nil, fmt.Errorf("VAULT_PEERS is empty")
	}
	recipients, err := recovery.ParseRecipients(getenv("RECOVERY_RECIPIENTS"))
	if err != nil {
		return nil, fmt.Errorf("RECOVERY_RECIPIENTS: %w", err)
	}
	c.Recipients = recipients
	k, err := strconv.Atoi(getenv("RECOVERY_THRESHOLD"))
	if err != nil || k < 1 || k > len(recipients) {
		return nil, fmt.Errorf("RECOVERY_THRESHOLD must be 1 to %d, got %q", len(recipients), getenv("RECOVERY_THRESHOLD"))
	}
	c.Threshold = k
	raw, err := hex.DecodeString(getenv("OPERATOR_KEY"))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("OPERATOR_KEY must be a hex Ed25519 public key")
	}
	c.OperatorKey = raw
	return c, nil
}

// vaultPin and edgePin accept any witnessed release of the repo. The minimum tags
// do the rest, because an old vault can't name a release that doesn't exist yet.
func (c *Config) vaultPin() string { return c.VaultRepo }
func (c *Config) edgePin() string  { return c.EdgeRepo }
