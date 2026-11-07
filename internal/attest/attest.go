// Package attest verifies Tinfoil attestation documents with tinfoil-go. Only the
// vault and vaultctl use it; the edge relies on the commitment instead.
package attest

import (
	"fmt"
	"time"

	"crypto/ecdh"

	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"

	"github.com/fount-labs/fount-mail-vault/wire"
)

const transferKeyID = "transfer"

// Peer is what a document proved.
type Peer struct {
	Key                *ecdh.PublicKey `json:"-"`
	KeyFingerprint     string          `json:"key_fingerprint"`
	Repo               string          `json:"repo"`
	Tag                string          `json:"tag"`
	FreshnessExpiresAt *time.Time      `json:"freshness_expires_at,omitempty"`
}

type Verifier struct{ v *verify.Verifier }

func NewVerifier() (*Verifier, error) {
	v, err := verify.NewVerifier()
	if err != nil {
		return nil, err
	}
	return &Verifier{v: v}, nil
}

// CheckPin fails at boot on a pin tinfoil-go can't use.
func (t *Verifier) CheckPin(pin string) error {
	if err := t.v.CheckRepoVerifiability(pin); err != nil {
		return fmt.Errorf("pin %q: %w", pin, err)
	}
	return nil
}

// Verify checks hardware, provenance against pin, freshness, and the nonce, then
// returns the endorsed transfer key. It does no network I/O.
func (t *Verifier) Verify(doc, nonce []byte, pin string) (*Peer, error) {
	verified, err := t.v.VerifyV3(doc, nonce, pin)
	if err != nil {
		return nil, err
	}
	spki, ok := verified.CryptoMaterialData(transferKeyID, document.KeySPKIV1Format)
	if !ok {
		return nil, fmt.Errorf("attestation endorses no %q key", transferKeyID)
	}
	key, err := wire.ParseEndorsedKey(spki)
	if err != nil {
		return nil, err
	}
	p := &Peer{Key: key, KeyFingerprint: wire.Fingerprint(key), Repo: verified.ConfigRepo(), Tag: verified.CodeTag()}
	if exp := verified.FreshnessExpiresAt(); !exp.IsZero() {
		p.FreshnessExpiresAt = &exp
	}
	return p, nil
}
