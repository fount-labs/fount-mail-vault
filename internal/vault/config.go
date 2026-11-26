// Package vault holds the Fount Mail keyset in enclave memory and hands it only
// to verified vaults and edges.
package vault

import (
	"crypto/ecdh"
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
	// RecipientKeys are the Recipients' X25519 keys, in the same order: share
	// i+1 must be sealed from RecipientKeys[i].
	RecipientKeys []*ecdh.PublicKey
	Threshold     int // RECOVERY_THRESHOLD: shares needed to restore
	OperatorKey   ed25519.PublicKey

	// CoordinatorMode is COORDINATOR_MODE=1: this is the Cloud vault pair,
	// its EDGE_REPO is the coordinator's config repo, and it keeps the
	// generation keyset and the coordinator's register
	// (docs/COORDINATOR-COUNTER.md).
	CoordinatorMode bool
	// GenerationKey is GENERATION_AUTHORITY_KEY, the generation keyset's
	// public key, base64: empty only in a release that may generate one.
	GenerationKey string
	// GenerationFloor and CountFloor are GENERATION_FLOOR and COUNT_FLOOR:
	// where a new register starts, at /generate-generation, and below which
	// no register is taken. Required in coordinator mode, even as 0, so a
	// release after a total loss can't forget them.
	GenerationFloor uint64
	CountFloor      uint64
	// CoordinatorHosts is COORDINATOR_HOSTS: the hostnames Fount's own
	// coordinator serves. A boot is only for an enclave whose attested TLS
	// key is the one serving one of them, so a copy of the public release
	// in someone else's Tinfoil account, which can't serve Fount's hostname,
	// can't take a generation (vault review H2, broker review H3). Required
	// with GENERATION_AUTHORITY_KEY, since that's the release that boots.
	CoordinatorHosts []string
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
	for _, r := range recipients {
		key, err := recovery.RecipientKey(r)
		if err != nil {
			return nil, fmt.Errorf("RECOVERY_RECIPIENTS: %w", err)
		}
		c.RecipientKeys = append(c.RecipientKeys, key)
	}
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
	if err := c.loadCoordinator(getenv); err != nil {
		return nil, err
	}
	return c, nil
}

// loadCoordinator reads the Cloud vault's settings. A mail vault sets none of
// them.
func (c *Config) loadCoordinator(getenv func(string) string) error {
	mode := getenv("COORDINATOR_MODE")
	c.GenerationKey = getenv("GENERATION_AUTHORITY_KEY")
	floor, count := getenv("GENERATION_FLOOR"), getenv("COUNT_FLOOR")
	switch mode {
	case "":
		if c.GenerationKey != "" || floor != "" || count != "" || getenv("COORDINATOR_HOSTS") != "" {
			return fmt.Errorf("GENERATION_AUTHORITY_KEY, GENERATION_FLOOR, COUNT_FLOOR and COORDINATOR_HOSTS need COORDINATOR_MODE=1")
		}
		return nil
	case "1":
		c.CoordinatorMode = true
		if len(c.Peers) != 2 {
			return fmt.Errorf("COORDINATOR_MODE needs exactly two VAULT_PEERS: the register lives on both")
		}
	default:
		return fmt.Errorf("COORDINATOR_MODE must be 1 or unset, got %q", mode)
	}
	for _, h := range strings.Split(getenv("COORDINATOR_HOSTS"), ",") {
		if h = strings.TrimSpace(h); h == "" {
			continue
		}
		if strings.ContainsAny(h, "/?#@: ") {
			return fmt.Errorf("COORDINATOR_HOSTS entry %q must be a bare hostname", h)
		}
		c.CoordinatorHosts = append(c.CoordinatorHosts, h)
	}
	if c.GenerationKey != "" && len(c.CoordinatorHosts) == 0 {
		return fmt.Errorf("GENERATION_AUTHORITY_KEY needs COORDINATOR_HOSTS: a boot is only for the coordinator serving one of them")
	}
	if c.GenerationKey != "" {
		if _, err := wire.ParseAuthorityKey(c.GenerationKey); err != nil {
			return fmt.Errorf("GENERATION_AUTHORITY_KEY: %w", err)
		}
		if c.Commitment == "" {
			return fmt.Errorf("GENERATION_AUTHORITY_KEY is set but KEYSET_COMMITMENT isn't")
		}
	}
	var err error
	if c.GenerationFloor, err = strconv.ParseUint(floor, 10, 63); err != nil {
		return fmt.Errorf("GENERATION_FLOOR must be a number, 0 for a first register, got %q", floor)
	}
	if c.CountFloor, err = strconv.ParseUint(count, 10, 63); err != nil {
		return fmt.Errorf("COUNT_FLOOR must be a number, 0 for a first register, got %q", count)
	}
	return nil
}

// vaultPin and edgePin accept any witnessed release of the repo. The minimum tags
// do the rest, because an old vault can't name a release that doesn't exist yet.
func (c *Config) vaultPin() string { return c.VaultRepo }
func (c *Config) edgePin() string  { return c.EdgeRepo }
