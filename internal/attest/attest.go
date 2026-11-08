// Package attest verifies Tinfoil attestation documents with tinfoil-go. Only the
// vault and vaultctl use it; the edge relies on the commitment instead.
package attest

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	Key            *ecdh.PublicKey `json:"-"`
	KeyFingerprint string          `json:"key_fingerprint"`
	Repo           string          `json:"repo"`
	Tag            string          `json:"tag"`
	// ChipID is the AMD CHIP_ID from the report: two enclaves with the same one run
	// on the same physical machine.
	ChipID             string     `json:"chip_id"`
	FreshnessExpiresAt *time.Time `json:"freshness_expires_at,omitempty"`
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
	chip, err := ChipID(doc)
	if err != nil {
		return nil, err
	}
	p := &Peer{Key: key, KeyFingerprint: wire.Fingerprint(key), Repo: verified.ConfigRepo(), Tag: verified.CodeTag(), ChipID: chip}
	if exp := verified.FreshnessExpiresAt(); !exp.IsZero() {
		p.FreshnessExpiresAt = &exp
	}
	return p, nil
}

// SNP report offsets, from AMD's SEV-SNP ABI (the ATTESTATION_REPORT structure).
const (
	chipIDOffset = 0x1A0
	chipIDSize   = 64
)

// ChipID reads CHIP_ID from a document's SNP report. tinfoil-go doesn't expose it,
// but it refuses a masked one, so a document Verify accepted always carries it, and
// the report bytes are the ones it authenticated.
func ChipID(doc []byte) (string, error) {
	var d struct {
		CPUEvidence struct {
			Report string `json:"report_base64"`
		} `json:"cpu_evidence"`
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		return "", fmt.Errorf("reading the SNP report: %w", err)
	}
	report, err := base64.StdEncoding.DecodeString(d.CPUEvidence.Report)
	if err != nil {
		return "", fmt.Errorf("reading the SNP report: %w", err)
	}
	if len(report) < chipIDOffset+chipIDSize {
		return "", fmt.Errorf("SNP report is %d bytes, too short for CHIP_ID", len(report))
	}
	return hex.EncodeToString(report[chipIDOffset : chipIDOffset+chipIDSize]), nil
}
