package vault

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/fount-labs/fount-mail-vault/internal/attest"
)

// Who may boot a generation, and how often (security review 2026-11-24 H2,
// broker review H3). A genuine instance of an allowed coordinator release,
// deployed by anyone, used to fence the real one with every boot.

const (
	// bootBurst boots may come at once, and one more every bootRefill.
	bootBurst  = 4
	bootRefill = 10 * time.Minute
)

var errBootRate = fmt.Errorf("more than %d coordinator boots, then one per %s: wait, or find what keeps booting", bootBurst, bootRefill)

// bootStats is /status's coordinator.boots, for alerting on every move.
type bootStats struct {
	Count       int       `json:"count"`
	RateLimited int       `json:"rate_limited"`
	WrongHost   int       `json:"wrong_host"`
	Allowance   float64   `json:"allowance"`
	LastAt      time.Time `json:"last_at,omitzero"`
	LastGen     uint64    `json:"last_generation,omitempty"`
	LastRepo    string    `json:"last_repo,omitempty"`
	LastTag     string    `json:"last_tag,omitempty"`
	LastChipID  string    `json:"last_chip_id,omitempty"`
	LastKeyFP   string    `json:"last_transfer_key_fp,omitempty"`
	LastTLSFP   string    `json:"last_tls_key_fp,omitempty"`

	tokens   float64
	refilled time.Time
}

// take spends one boot from the allowance. Called with s.mu held.
func (b *bootStats) take(now time.Time) error {
	if b.refilled.IsZero() {
		b.tokens, b.refilled = bootBurst, now
	}
	b.tokens = min(bootBurst, b.tokens+float64(now.Sub(b.refilled))/float64(bootRefill))
	b.refilled = now
	b.Allowance = b.tokens
	if b.tokens < 1 {
		b.RateLimited++
		return errBootRate
	}
	b.tokens--
	b.Allowance = b.tokens
	return nil
}

func (s *Server) takeBoot() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.boots.take(time.Now())
}

// refundBoot gives back a boot that moved nothing, such as one refused
// because a vault was down, so a coordinator retrying through an outage
// isn't then held back.
func (s *Server) refundBoot() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.boots.tokens = min(bootBurst, s.boots.tokens+1)
	s.boots.Allowance = s.boots.tokens
}

func (s *Server) recordBoot(peer *attest.Peer, generation uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := &s.boots
	b.Count++
	b.LastAt, b.LastGen = time.Now().UTC(), generation
	b.LastRepo, b.LastTag, b.LastChipID, b.LastKeyFP, b.LastTLSFP = peer.Repo, peer.Tag, peer.ChipID, peer.KeyFingerprint, peer.TLSKeyFP
}

// checkCoordinatorHost is whether peer's attested TLS key is the one serving
// one of COORDINATOR_HOSTS now. The certificate chain is checked for the
// hostname as any TLS client would, so only the enclave Fount's hostname
// routes to passes; a copy in another account serves another name with
// another key.
func (s *Server) checkCoordinatorHost(ctx context.Context, peer *attest.Peer) error {
	if peer.TLSKeyFP == "" {
		return errors.New("the document endorses no TLS key")
	}
	var errs []error
	for _, host := range s.cfg.CoordinatorHosts {
		fp, err := s.servingKey(ctx, host)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", host, err))
			continue
		}
		if fp == peer.TLSKeyFP {
			return nil
		}
		errs = append(errs, fmt.Errorf("%s serves TLS key %.16s…, the requester attests %.16s…", host, fp, peer.TLSKeyFP))
	}
	s.mu.Lock()
	s.boots.WrongHost++
	s.mu.Unlock()
	return fmt.Errorf("not the coordinator serving %v: %w", s.cfg.CoordinatorHosts, errors.Join(errs...))
}

// tlsKeyServing is the SPKI SHA-256 of the leaf certificate host serves,
// after the chain verified for host. Any answer will do; only the handshake
// counts.
func tlsKeyServing(client *http.Client, base func(string) string) func(ctx context.Context, host string) (string, error) {
	return func(ctx context.Context, host string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base(host)+"/health", nil)
		if err != nil {
			return "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<12))
		resp.Body.Close()
		if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 || len(resp.TLS.VerifiedChains) == 0 {
			return "", errors.New("no verified TLS certificate")
		}
		return spkiFP(resp.TLS.PeerCertificates[0])
	}
}

func spkiFP(cert *x509.Certificate) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:]), nil
}
