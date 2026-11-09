package vault

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/fount-labs/fount-mail-vault/internal/attest"
	"github.com/fount-labs/fount-mail-vault/internal/recovery"
	"github.com/fount-labs/fount-mail-vault/wire"
)

const (
	nonceLifetime  = 2 * time.Minute
	maxNonces      = 256
	maxRefusals    = 20
	maxPending     = 32
	selfCheckEvery = time.Hour
	retryFirst     = 5 * time.Second
	retryMax       = 2 * time.Minute
)

var (
	errNoKeyset   = errors.New("this vault holds no keyset")
	errHeld       = errors.New("this vault already holds a keyset")
	errSendHeld   = errors.New("this vault already holds a send keyset")
	errNoSendSlot = errors.New("this release has a send commitment, so it can't generate a send keyset")
)

// Verifier is attest.Verifier, behind an interface so tests can stand in for hardware.
type Verifier interface {
	Verify(doc, nonce []byte, pin string) (*attest.Peer, error)
}

type peerKind string

const (
	kindVault peerKind = "vault"
	kindEdge  peerKind = "edge"
)

type nonceUse string

const (
	useTransfer nonceUse = "transfer"
	useOperator nonceUse = "operator"
)

type issuedNonce struct {
	use     nonceUse
	expires time.Time
}

type refusal struct {
	At     time.Time `json:"at"`
	Stage  string    `json:"stage"`
	Reason string    `json:"reason"`
}

type peerRecord struct {
	Kind peerKind `json:"kind"`
	*attest.Peer
}

type Server struct {
	cfg      *Config
	transfer *ecdh.PrivateKey
	attester wire.Attester
	verifier Verifier
	client   *http.Client
	booted   time.Time

	mu          sync.Mutex
	keyset      *wire.Keyset
	s3          *wire.S3Credentials
	source      string
	sendKeyset  *wire.SendKeyset
	sendSource  string
	nonces      map[string]issuedNonce
	refusals    []refusal
	lastPeer    *peerRecord
	self        *attest.Peer
	selfErr     string
	selfChecked time.Time
	bundle      *recovery.Bundle
	pending     [][]byte
}

func NewServer(cfg *Config, transfer *ecdh.PrivateKey, a wire.Attester, v Verifier, client *http.Client) *Server {
	return &Server{
		cfg:      cfg,
		transfer: transfer,
		attester: a,
		verifier: v,
		client:   client,
		booted:   time.Now(),
		nonces:   make(map[string]issuedNonce),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /status", s.handleStatus)
	mux.HandleFunc("POST /generate", s.handleGenerate)
	mux.HandleFunc("POST /generate-send", s.handleGenerateSend)
	mux.HandleFunc("POST /transfer/begin", s.handleBegin)
	mux.HandleFunc("POST /transfer/finish", s.handleFinish)
	mux.HandleFunc("GET /recovery/bundle", s.handleBundle)
	mux.HandleFunc("POST /operator/begin", s.handleOperatorBegin)
	mux.HandleFunc("POST /recovery/share", s.handleShare)
	mux.HandleFunc("POST /operator/import", s.handleImport)
	return mux
}

// Run keeps the vault's own witness checked and, while it's empty, keeps trying
// to restore from its peers. It returns when ctx ends.
func (s *Server) Run(ctx context.Context) {
	go s.restoreLoop(ctx)
	for {
		if err := s.selfCheck(ctx); err != nil {
			log.Printf("self check: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(selfCheckEvery):
		}
	}
}

func (s *Server) restoreLoop(ctx context.Context) {
	wait := retryFirst
	for ctx.Err() == nil {
		for _, peer := range s.cfg.Peers {
			if s.complete() {
				return
			}
			if err := s.PullFrom(ctx, "https://"+peer); err != nil {
				log.Printf("restore from %s: %v", peer, err)
			}
		}
		if s.complete() {
			return
		}
		if s.holds() {
			log.Printf("holding the keyset, but no peer has the committed send keyset; asking again in %s", wait)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, retryMax)
	}
}

// PullFrom restores the keyset, and the send keyset if the holder has it, from
// another vault. The holder must verify as a vault release, but may be older than
// this one, because that's how upgrades work. A vault that holds the keyset but
// not the committed send keyset pulls again for the send keyset.
func (s *Server) PullFrom(ctx context.Context, base string) error {
	if s.complete() {
		return errHeld
	}
	check := func(doc, nonce []byte) (*ecdh.PublicKey, error) {
		peer, err := s.verifier.Verify(doc, nonce, s.cfg.vaultPin())
		if err != nil {
			return nil, err
		}
		s.recordPeer(kindVault, peer)
		return peer.Key, nil
	}
	want := wire.Commitments{Keyset: s.cfg.Commitment, Send: s.cfg.SendCommitment}
	got, err := wire.PullKeysets(ctx, s.client, base, s.transfer, s.attester, check, want)
	if err != nil {
		return err
	}
	keyset, send := s.install(got.Keyset, got.SendKeyset, got.S3, "pulled from "+base)
	elapsed := got.Elapsed.Round(time.Millisecond)
	if keyset {
		log.Printf("restored keyset %s from %s in %s", got.Keyset.Commitment(), base, elapsed)
	}
	if send {
		log.Printf("restored send keyset %s from %s in %s", got.SendKeyset.Commitment(), base, elapsed)
	}
	if !keyset && !send {
		return errors.New("the holder has no send keyset")
	}
	return nil
}

func (s *Server) holds() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keyset != nil
}

// complete is whether this vault holds everything its release commits to. A
// release with no send commitment doesn't wait for a send keyset.
func (s *Server) complete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keyset != nil && (s.cfg.SendCommitment == "" || s.sendKeyset != nil)
}

// install keeps the first keyset and the first send keyset. With a commitment
// there's only one possible keyset; without one, a generate and a pull could
// race, and either is fine. A send keyset only exists in a release with a keyset
// commitment, so it always sits beside the committed keyset. It reports what it
// installed.
func (s *Server) install(k *wire.Keyset, send *wire.SendKeyset, s3 *wire.S3Credentials, source string) (keyset, sendKeyset bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keyset == nil {
		s.keyset, s.source, s.bundle = k, source, nil
		keyset = true
		if s.s3 == nil {
			s.s3 = s3
		}
	}
	if send != nil && s.sendKeyset == nil {
		s.sendKeyset, s.sendSource = send, source
		sendKeyset = true
	}
	return keyset, sendKeyset
}

// selfCheck verifies this vault's own document. It's what the minimum tag for
// vault peers comes from, and it reports when the witness expires.
func (s *Server) selfCheck(ctx context.Context) error {
	self, err := s.verifySelf(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.selfChecked = time.Now().UTC()
	if err != nil {
		s.selfErr = err.Error()
		return err
	}
	s.self, s.selfErr = self, ""
	return nil
}

func (s *Server) verifySelf(ctx context.Context) (*attest.Peer, error) {
	nonce, err := wire.RandomNonce()
	if err != nil {
		return nil, err
	}
	doc, err := s.attester.Attest(ctx, nonce)
	if err != nil {
		return nil, fmt.Errorf("attesting to self: %w", err)
	}
	self, err := s.verifier.Verify(doc, nonce, s.cfg.vaultPin())
	if err != nil {
		return nil, fmt.Errorf("verifying self: %w", err)
	}
	if !self.Key.Equal(s.transfer.PublicKey()) {
		return nil, errors.New("verifying self: the document endorses another transfer key")
	}
	if !validTag(self.Tag) {
		return nil, fmt.Errorf("own release tag %q isn't a version", self.Tag)
	}
	return self, nil
}

// ownTag is the floor for vault peers. If the self check hasn't passed yet, it
// runs one, and without it the vault refuses every vault peer.
func (s *Server) ownTag(ctx context.Context) (string, error) {
	s.mu.Lock()
	self := s.self
	s.mu.Unlock()
	if self != nil {
		return self.Tag, nil
	}
	if err := s.selfCheck(ctx); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.self.Tag, nil
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := map[string]any{
		"uptime_s":               int(time.Since(s.booted).Seconds()),
		"has_keyset":             s.keyset != nil,
		"config_commitment":      s.cfg.Commitment,
		"has_s3":                 s.s3 != nil,
		"source":                 s.source,
		"has_send_keyset":        s.sendKeyset != nil,
		"config_send_commitment": s.cfg.SendCommitment,
		"send_source":            s.sendSource,
		"transfer_key_fp":        wire.Fingerprint(s.transfer.PublicKey()),
		"edge_min_tag":           s.cfg.EdgeMinTag,
		"peers":                  s.cfg.Peers,
		"recovery": map[string]int{
			"threshold":      s.cfg.Threshold,
			"recipients":     len(s.cfg.Recipients),
			"pending_shares": len(s.pending),
		},
		"self_checked_at":  s.selfChecked,
		"self_check_error": s.selfErr,
		"last_peer":        s.lastPeer,
		"refusals":         s.refusals,
	}
	if s.keyset != nil {
		status["keyset_commitment"] = s.keyset.Commitment()
	}
	if s.sendKeyset != nil {
		status["send_keyset_commitment"] = s.sendKeyset.Commitment()
		if pub, err := sendPublic(s.sendKeyset); err == nil {
			status["send_public"] = pub
		} else {
			status["send_public_error"] = err.Error()
		}
	}
	if s.self != nil {
		status["release_tag"] = s.self.Tag
		status["freshness_expires_at"] = s.self.FreshnessExpiresAt
		status["chip_id"] = s.self.ChipID
		if s.lastPeer != nil && s.lastPeer.Peer != nil {
			// Two vaults on one machine fail together, which leaves only the shares.
			status["same_chip_as_last_peer"] = s.lastPeer.Peer.ChipID == s.self.ChipID
		}
	}
	writeJSON(w, http.StatusOK, status)
}

// handleGenerate works once, and only in a release with no commitment. Anyone may
// call it, because the keys it makes never leave the enclave unsealed.
func (s *Server) handleGenerate(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.Commitment != "" {
		writeError(w, http.StatusConflict, errors.New("this release has a commitment, so it can't generate a keyset"))
		return
	}
	if s.holds() {
		writeError(w, http.StatusConflict, errHeld)
		return
	}
	k, err := wire.Generate()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.install(k, nil, nil, "generated")
	s.mu.Lock()
	installed := s.keyset
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"commitment": installed.Commitment()})
}

// handleGenerateSend works once, and only in a release with a keyset commitment
// and no send commitment, on a vault that holds the keyset. Anyone may call it,
// for the same reason as handleGenerate. The keyset commitment is what keeps it
// apart from the first generate: the send keyset rides with the committed keyset.
func (s *Server) handleGenerateSend(w http.ResponseWriter, _ *http.Request) {
	if s.cfg.SendCommitment != "" {
		writeError(w, http.StatusConflict, errNoSendSlot)
		return
	}
	if s.cfg.Commitment == "" {
		writeError(w, http.StatusConflict, errors.New("this release has no keyset commitment, so it can't generate a send keyset"))
		return
	}
	s.mu.Lock()
	keyset, held := s.keyset, s.sendKeyset != nil
	s.mu.Unlock()
	if keyset == nil {
		writeError(w, http.StatusConflict, errNoKeyset)
		return
	}
	if held {
		writeError(w, http.StatusConflict, errSendHeld)
		return
	}
	send, err := wire.GenerateSend()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if _, installed := s.install(keyset, send, nil, "generated"); !installed {
		writeError(w, http.StatusConflict, errSendHeld)
		return
	}
	pub, err := sendPublic(send)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"send_commitment": send.Commitment(), "send_public": pub})
}

func (s *Server) handleBundle(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keyset == nil {
		writeError(w, http.StatusConflict, errNoKeyset)
		return
	}
	if s.bundle == nil {
		b, err := recovery.NewBundle(s.keyset, s.cfg.Recipients, s.cfg.Threshold)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.bundle = b
	}
	writeJSON(w, http.StatusOK, s.bundle)
}

// issueNonce makes a one-use nonce for one kind of exchange.
func (s *Server) issueNonce(use nonceUse) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for n, issued := range s.nonces {
		if now.After(issued.expires) {
			delete(s.nonces, n)
		}
	}
	if len(s.nonces) >= maxNonces {
		return "", errTooMany
	}
	nonce, err := wire.RandomNonce()
	if err != nil {
		return "", err
	}
	encoded := hex.EncodeToString(nonce)
	s.nonces[encoded] = issuedNonce{use: use, expires: now.Add(nonceLifetime)}
	return encoded, nil
}

var errTooMany = errors.New("too many open exchanges")

// consumeNonce makes each challenge single-use, so a document or a signed request
// for it can't be replayed, even by someone who saw the first exchange.
func (s *Server) consumeNonce(encoded string, use nonceUse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	issued, ok := s.nonces[encoded]
	if !ok {
		return errors.New("unknown or already used nonce")
	}
	delete(s.nonces, encoded)
	if issued.use != use {
		return fmt.Errorf("nonce was issued for %s, not %s", issued.use, use)
	}
	if time.Now().After(issued.expires) {
		return errors.New("expired nonce")
	}
	return nil
}

func (s *Server) recordPeer(kind peerKind, peer *attest.Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastPeer = &peerRecord{Kind: kind, Peer: peer}
}

func (s *Server) refuse(w http.ResponseWriter, stage string, err error) {
	s.mu.Lock()
	s.refusals = append(s.refusals, refusal{At: time.Now().UTC(), Stage: stage, Reason: fmt.Sprintf("%.300v", err)})
	if len(s.refusals) > maxRefusals {
		s.refusals = s.refusals[len(s.refusals)-maxRefusals:]
	}
	s.mu.Unlock()
	log.Printf("refused at %s: %v", stage, err)
	writeError(w, http.StatusForbidden, fmt.Errorf("refused at %s: %w", stage, err))
}

func decode(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding request: %w", err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writing response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
