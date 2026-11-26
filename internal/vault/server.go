package vault

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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
	maxSpentPulls  = 1 << 14
	maxSpentStrict = 1 << 12
	maxRefusals    = 20
	// maxSharesPerRecipient is how many shares one recipient may submit per
	// nonce lifetime, so even a stolen identity can't fill spentShare.
	maxSharesPerRecipient = 8
	selfCheckEvery        = time.Hour
	retryFirst            = 5 * time.Second
	retryMax              = 2 * time.Minute
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

// nonceUseByte is a nonce's first byte, so a nonce says what it was issued for.
var nonceUseByte = map[nonceUse]byte{useTransfer: 1, useOperator: 2}

// spentClass is where a consumed nonce is kept until it expires. Each class
// has its own budget, so a flood of one can't refuse another.
type spentClass string

const (
	// spentPull is a pull's: it has no side effect, and the box is sealed to
	// the attested key, so replaying an evicted one gives nobody anything.
	// The oldest is evicted when it's full.
	spentPull spentClass = "pull"
	// spentBoot, spentShare and spentImport have side effects, and are kept
	// until they expire. Only a boot proof, an opened share box or an
	// operator signature gets a nonce into one.
	spentBoot   spentClass = "boot"
	spentShare  spentClass = "share"
	spentImport spentClass = "import"
)

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
	nonceKey    []byte
	spent       map[spentClass]*spentSet
	refusals    []refusal
	lastPeer    *peerRecord
	self        *attest.Peer
	selfErr     string
	selfChecked time.Time
	bundle      *recovery.Bundle
	// pending holds at most one share per recipient, keyed by its index, and
	// shareTimes when each recipient last submitted (maxSharesPerRecipient).
	pending    map[int][]byte
	shareTimes map[int][]time.Time
	// beforeCombine, set by tests only, runs as a restore attempt begins,
	// outside the lock.
	beforeCombine func()

	// The Cloud vault's generation keyset and register (counter.go,
	// register.go). instance is drawn per process.
	genKeyset    *wire.GenerationKeyset
	genSource    string
	peerMAC      []byte
	lastSync     *syncRecord
	reg          register
	instance     string
	proposeMu    sync.Mutex
	counterCalls chan struct{}
	loadMu       sync.Mutex
	loadNext     *loadFlight
	loadRunning  bool
	peerBase     func(host string) string
	boots        bootStats
	// servingKey is the TLS key a coordinator host serves; tests replace it.
	servingKey func(ctx context.Context, host string) (string, error)
}

func NewServer(cfg *Config, transfer *ecdh.PrivateKey, a wire.Attester, v Verifier, client *http.Client) *Server {
	instance := make([]byte, 16)
	nonceKey := make([]byte, 32)
	if _, err := rand.Read(instance); err != nil {
		panic(err)
	}
	if _, err := rand.Read(nonceKey); err != nil {
		panic(err)
	}
	s := &Server{
		cfg:      cfg,
		transfer: transfer,
		attester: a,
		verifier: v,
		client:   client,
		booted:   time.Now(),
		nonceKey: nonceKey,
		spent: map[spentClass]*spentSet{
			spentPull:   newSpentSet(maxSpentPulls, true),
			spentBoot:   newSpentSet(maxSpentStrict, false),
			spentShare:  newSpentSet(maxSpentStrict, false),
			spentImport: newSpentSet(maxSpentStrict, false),
		},
		instance:     hex.EncodeToString(instance),
		counterCalls: make(chan struct{}, maxCounterCalls),
		peerBase:     func(host string) string { return "https://" + host },
	}
	s.servingKey = tlsKeyServing(client, func(host string) string { return s.peerBase(host) })
	return s
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
	mux.HandleFunc("POST /generate-generation", s.handleGenerateGeneration)
	mux.HandleFunc("POST "+wire.CounterPath, s.handleCounter)
	mux.HandleFunc("POST "+pathHead, s.handlePeer)
	mux.HandleFunc("POST "+pathApply, s.handlePeer)
	return mux
}

// Run keeps the vault's own witness checked and, while it's empty, keeps trying
// to restore from its peers. It returns when ctx ends.
func (s *Server) Run(ctx context.Context) {
	go s.restoreLoop(ctx)
	if s.cfg.CoordinatorMode {
		go s.syncLoop(ctx)
	}
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
			if err := s.PullFrom(ctx, s.peerBase(peer)); err != nil {
				log.Printf("restore from %s: %v", peer, err)
			}
		}
		if s.complete() {
			return
		}
		if s.holds() {
			log.Printf("holding the keyset, but no peer has the committed send keyset or generation keyset; asking again in %s", wait)
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
	want := wire.Commitments{Keyset: s.cfg.Commitment, Send: s.cfg.SendCommitment, Generation: s.cfg.GenerationKey}
	got, err := wire.PullKeysets(ctx, s.client, base, s.transfer, s.attester, check, want)
	if err != nil {
		return err
	}
	keyset, send := s.install(got.Keyset, got.SendKeyset, got.S3, "pulled from "+base)
	gen, genErr := s.installPulledGeneration(got)
	elapsed := got.Elapsed.Round(time.Millisecond)
	if keyset {
		log.Printf("restored keyset %s from %s in %s", got.Keyset.Commitment(), base, elapsed)
	}
	if send {
		log.Printf("restored send keyset %s from %s in %s", got.SendKeyset.Commitment(), base, elapsed)
	}
	if gen {
		log.Printf("restored generation keyset %s and the register from %s in %s", got.GenerationKeyset.AuthorityKey(), base, elapsed)
	}
	if genErr != nil {
		return genErr
	}
	if !keyset && !send && !gen {
		return errors.New("the holder has nothing this vault is missing")
	}
	return nil
}

// installPulledGeneration keeps a pulled generation keyset and its register.
func (s *Server) installPulledGeneration(got *wire.PullResult) (bool, error) {
	if got.GenerationKeyset == nil || !s.cfg.CoordinatorMode {
		return false, nil
	}
	var history []regState
	if err := json.Unmarshal(got.Register, &history); err != nil {
		return false, fmt.Errorf("the holder's register: %w", err)
	}
	return s.installGeneration(got.GenerationKeyset, history, "pulled from a vault")
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
	return s.keyset != nil && (s.cfg.SendCommitment == "" || s.sendKeyset != nil) && (s.cfg.GenerationKey == "" || s.genKeyset != nil)
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
	if s.cfg.CoordinatorMode {
		cloud := map[string]any{
			"config_authority_key": s.cfg.GenerationKey,
			"generation_floor":     s.cfg.GenerationFloor,
			"count_floor":          s.cfg.CountFloor,
			"has_generation":       s.genKeyset != nil,
			"generation_source":    s.genSource,
			"instance":             s.instance,
			"last_sync":            s.lastSync,
			"coordinator_hosts":    s.cfg.CoordinatorHosts,
			"boots":                s.boots,
		}
		if s.genKeyset != nil {
			cloud["authority_key"] = s.genKeyset.AuthorityKey()
		}
		if reg := s.registerStatus(); reg != nil {
			cloud["register"] = reg
		}
		status["coordinator"] = cloud
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
	if s.cfg.CoordinatorMode {
		writeError(w, http.StatusConflict, errors.New("a Cloud vault holds no send keyset"))
		return
	}
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

// issueNonce makes a nonce for one kind of exchange. It keeps nothing: the
// nonce carries its use and expiry under a MAC with this process's key, so
// nobody can run the vault out of nonces (security review H1). Single use is
// spend's, once the exchange has shown what it is.
//
// Layout: use (1) | expiry, Unix ms (8) | random (7) | MAC (16).
func (s *Server) issueNonce(use nonceUse) (string, error) {
	nonce := make([]byte, wire.NonceSize)
	nonce[0] = nonceUseByte[use]
	binary.BigEndian.PutUint64(nonce[1:9], uint64(time.Now().Add(nonceLifetime).UnixMilli()))
	if _, err := rand.Read(nonce[9:16]); err != nil {
		return "", err
	}
	copy(nonce[16:], s.nonceMAC(nonce[:16]))
	return hex.EncodeToString(nonce), nil
}

func (s *Server) nonceMAC(body []byte) []byte {
	m := hmac.New(sha256.New, s.nonceKey)
	m.Write([]byte("fount-mail-vault/nonce/v1\x00"))
	m.Write(body)
	return m.Sum(nil)[:16]
}

// checkNonce is whether this process issued the nonce, for use, and it hasn't
// expired. It doesn't spend it.
func (s *Server) checkNonce(encoded string, use nonceUse) (time.Time, error) {
	nonce, err := hex.DecodeString(encoded)
	if err != nil || len(nonce) != wire.NonceSize || !hmac.Equal(s.nonceMAC(nonce[:16]), nonce[16:]) {
		return time.Time{}, errors.New("unknown nonce: this vault didn't issue it, or it restarted since")
	}
	if nonce[0] != nonceUseByte[use] {
		for other, b := range nonceUseByte {
			if b == nonce[0] {
				return time.Time{}, fmt.Errorf("nonce was issued for %s, not %s", other, use)
			}
		}
	}
	expires := time.UnixMilli(int64(binary.BigEndian.Uint64(nonce[1:9])))
	if time.Now().After(expires) {
		return time.Time{}, errors.New("expired nonce")
	}
	return expires, nil
}

// spend makes a checked nonce single-use within its class. It comes after
// whatever proves the exchange, so a request that proves nothing spends
// nothing, and a flood of pulls can't fill the sets boots and the operator
// use.
func (s *Server) spend(encoded string, expires time.Time, class spentClass) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spent[class].add(encoded, expires, time.Now())
}

var errTooMany = errors.New("too many open exchanges")

// spentSet is the nonces of one class spent and not yet expired, oldest first.
type spentSet struct {
	max   int
	evict bool
	at    map[string]time.Time
	order []string
}

func newSpentSet(max int, evict bool) *spentSet {
	return &spentSet{max: max, evict: evict, at: map[string]time.Time{}}
}

func (p *spentSet) add(nonce string, expires, now time.Time) error {
	if _, ok := p.at[nonce]; ok {
		return errors.New("already used nonce")
	}
	for len(p.order) > 0 {
		oldest := p.order[0]
		if exp, ok := p.at[oldest]; ok && now.Before(exp) && len(p.at) < p.max {
			break
		}
		if exp, ok := p.at[oldest]; ok && now.Before(exp) && !p.evict {
			return errTooMany
		}
		delete(p.at, oldest)
		p.order = p.order[1:]
	}
	p.at[nonce] = expires
	p.order = append(p.order, nonce)
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
