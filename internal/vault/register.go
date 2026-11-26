package vault

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/fount-labs/fount-mail-vault/wire"
)

// The coordinator's register (docs/COORDINATOR-COUNTER.md, "Replication"):
// the current coordinator generation, its key, and the security count, held
// in the memory of both Cloud vaults.
//
// It's a hash chain. Every change is a new state naming the hash of the one
// before, and a vault takes a state only if it extends the head it holds, so
// it takes at most one successor of any state. A change commits when the
// vault at VAULT_PEERS[0] takes it and then the vault at VAULT_PEERS[1]
// does, always in that order, so two changes racing from different vaults
// can't each win one of them. A change is answered only once both hold it.
//
// Every read and every change needs both vaults. Whichever vault handles a
// call first reads both heads: equal, it goes on; one a few states behind
// the other, which a change cut short or a restarted or just-promoted vault
// leaves, it brings that one up first; anything else (two different states
// at one version, or a gap wider than the history) is refused as diverged.
// Restarting one vault ends a divergence: it pulls the other's register with
// the keyset.
//
// Vaults talk to each other here with HMAC under a key derived from the
// generation keyset, which only vaults hold. Nothing on this path is secret,
// so nothing is sealed.

const (
	maxHistory     = 64
	peerCallTimout = 10 * time.Second
	syncEvery      = 15 * time.Second
	maxPeerBody    = 1 << 20
	stateLabel     = "fount-coordinator-register/state/v1\x00"
	peerMACInfo    = "fount-coordinator-register/peer/v1"
	peerReqLabel   = "fount-coordinator-register/peer/v1/request\x00"
	peerAnsLabel   = "fount-coordinator-register/peer/v1/answer\x00"
	pathHead       = "/register/head"
	pathApply      = "/register/apply"
	resultAccepted = "accepted"
	resultRejected = "rejected"
)

var (
	errRegisterUnavailable = errors.New("the register needs both vaults, and one didn't answer")
	errDiverged            = errors.New("the vaults' registers have diverged; restart one vault so it pulls the other's")
	errLostRace            = errors.New("another change reached the first vault first; try again")
	errNoGeneration        = errors.New("this vault holds no generation keyset")
)

// regState is one state of the register.
type regState struct {
	Version uint64 `json:"version"`
	// Prev is the hex hash of the state before, empty at version 0.
	Prev       string `json:"prev,omitempty"`
	Generation uint64 `json:"generation"`
	// Key is the coordinator key the generation's certificate names; nil
	// until the first boot.
	Key   []byte   `json:"key,omitempty"`
	Count uint64   `json:"count"`
	Swap  *regSwap `json:"swap,omitempty"`
	// Digest and Writer are the counted state's digest and the generation
	// whose version 2 cas set them; a boot keeps them. Empty and 0 for a
	// count set by a version 1 cas or the floors.
	Digest string `json:"digest,omitempty"`
	Writer uint64 `json:"writer,omitempty"`
}

// regSwap is the cas that made a state, so a retry after a lost answer is
// answered as the success it was.
type regSwap struct {
	Generation uint64 `json:"generation"`
	Prev       uint64 `json:"prev"`
	Next       uint64 `json:"next"`
}

func (s regState) hash() string {
	h := sha256.New()
	h.Write([]byte(stateLabel))
	var prev [32]byte
	if p, err := hex.DecodeString(s.Prev); err == nil && len(p) == 32 {
		copy(prev[:], p)
	}
	b := binary.BigEndian.AppendUint64(nil, s.Version)
	b = append(b, prev[:]...)
	b = binary.BigEndian.AppendUint64(b, s.Generation)
	b = append(b, byte(len(s.Key)))
	b = append(b, s.Key...)
	b = binary.BigEndian.AppendUint64(b, s.Count)
	if s.Swap == nil {
		b = append(b, 0)
	} else {
		b = append(b, 1)
		b = binary.BigEndian.AppendUint64(b, s.Swap.Generation)
		b = binary.BigEndian.AppendUint64(b, s.Swap.Prev)
		b = binary.BigEndian.AppendUint64(b, s.Swap.Next)
	}
	// Only a state a version 2 cas counted has these, so every other
	// state hashes as it did before, and vaults that predate version 2
	// still agree with this one on them.
	if s.Digest != "" || s.Writer != 0 {
		d, _ := hex.DecodeString(s.Digest)
		b = append(b, 2, byte(len(d)))
		b = append(b, d...)
		b = binary.BigEndian.AppendUint64(b, s.Writer)
	}
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func (s regState) valid() error {
	if s.Version == 0 {
		if s.Prev != "" {
			return errors.New("state 0 has a predecessor")
		}
	} else if p, err := hex.DecodeString(s.Prev); err != nil || len(p) != 32 {
		return errors.New("a state names its predecessor's hash")
	}
	if len(s.Key) != 0 && len(s.Key) != 32 {
		return errors.New("a state's key is 32 bytes")
	}
	if (s.Digest == "") != (s.Writer == 0) || (s.Digest != "" && !wire.ValidStateDigest(s.Digest)) {
		return errors.New("a state's digest is 32 bytes, with the generation that wrote it")
	}
	if s.Swap != nil && (s.Swap.Generation != s.Generation || s.Swap.Next != s.Count || s.Swap.Next <= s.Swap.Prev) {
		return errors.New("a state's swap doesn't match it")
	}
	return nil
}

// step checks that b follows a: a boot, or a cas.
func step(a, b regState) error {
	if b.Version != a.Version+1 || b.Prev != a.hash() {
		return fmt.Errorf("state %d doesn't follow state %d", b.Version, a.Version)
	}
	switch {
	case b.Generation == a.Generation+1:
		if len(b.Key) != 32 || b.Count != a.Count || b.Swap != nil || a.Digest != b.Digest || a.Writer != b.Writer {
			return fmt.Errorf("state %d boots a generation but changes more", b.Version)
		}
	case b.Generation == a.Generation:
		if len(a.Key) != 32 || !bytes.Equal(a.Key, b.Key) || b.Swap == nil || b.Swap.Prev != a.Count || b.Count <= a.Count {
			return fmt.Errorf("state %d isn't a swap of state %d", b.Version, a.Version)
		}
		if b.Digest != "" && b.Writer != b.Generation {
			return fmt.Errorf("state %d's digest names generation %d as its writer", b.Version, b.Writer)
		}
		if b.Count > wire.MaxCount || b.Count-a.Count > wire.MaxCountStep {
			return fmt.Errorf("state %d moves the count from %d to %d, past the bounds", b.Version, a.Count, b.Count)
		}
	default:
		return fmt.Errorf("state %d moves the generation by more than one", b.Version)
	}
	return nil
}

func validChain(chain []regState) error {
	if len(chain) == 0 {
		return errors.New("an empty chain")
	}
	for i, s := range chain {
		if err := s.valid(); err != nil {
			return err
		}
		if i > 0 {
			if err := step(chain[i-1], s); err != nil {
				return err
			}
		}
	}
	return nil
}

// register is this vault's copy: its recent states, oldest first.
type register struct {
	mu      sync.Mutex
	history []regState
}

func (r *register) snapshot() []regState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]regState(nil), r.history...)
}

func (r *register) head() (regState, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.history) == 0 {
		return regState{}, false
	}
	return r.history[len(r.history)-1], true
}

// install starts the register from a pull or a generate. It takes one only
// when it holds none.
func (r *register) install(history []regState) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.history) != 0 {
		return false
	}
	r.history = append([]regState(nil), history...)
	return true
}

// apply takes the states of chain that extend this vault's head. A chain
// whose tip this vault already holds is accepted too: a change delivered
// again. Anything else is rejected, and nothing changes.
func (r *register) apply(chain []regState) (string, error) {
	if err := validChain(chain); err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.history) == 0 {
		return "", errors.New("this vault holds no register")
	}
	head := r.history[len(r.history)-1]
	tip := chain[len(chain)-1]
	if tip.Version <= head.Version {
		th := tip.hash()
		for _, s := range r.history {
			if s.Version == tip.Version && s.hash() == th {
				return resultAccepted, nil
			}
		}
		return resultRejected, nil
	}
	hh, start := head.hash(), -1
	for i, s := range chain {
		if s.Version == head.Version && s.hash() == hh {
			start = i + 1
		}
	}
	if start < 0 && chain[0].Version == head.Version+1 && chain[0].Prev == hh {
		start = 0
	}
	if start < 0 {
		return resultRejected, nil
	}
	r.history = append(r.history, chain[start:]...)
	if n := len(r.history); n > maxHistory {
		r.history = append([]regState(nil), r.history[n-maxHistory:]...)
	}
	return resultAccepted, nil
}

// fromHistory is the part of history after the state at version, or nil if
// history doesn't hold that state with that hash.
func fromHistory(history []regState, s regState) []regState {
	h := s.hash()
	for i, st := range history {
		if st.Version == s.Version && st.hash() == h {
			return history[i:]
		}
	}
	return nil
}

// checkFloors refuses a register from before this release's floors.
func (c *Config) checkFloors(head regState) error {
	if head.Generation < c.GenerationFloor || head.Count < c.CountFloor {
		return fmt.Errorf("the register is at generation %d and count %d, below this release's floors %d and %d", head.Generation, head.Count, c.GenerationFloor, c.CountFloor)
	}
	return nil
}

func peerMACKey(seed []byte) []byte {
	k, err := hkdf.Key(sha256.New, seed, nil, peerMACInfo, 32)
	if err != nil {
		panic("hkdf: " + err.Error())
	}
	return k
}

// envelope carries a peer message and its MAC.
type envelope struct {
	Body []byte `json:"body"`
	MAC  []byte `json:"mac"`
}

type peerRequest struct {
	Nonce string     `json:"nonce"`
	Chain []regState `json:"chain,omitempty"`
}

type peerAnswer struct {
	// Instance is drawn per process, so a caller can tell two vaults from
	// one vault answering twice.
	Instance string     `json:"instance"`
	Result   string     `json:"result,omitempty"`
	History  []regState `json:"history"`
}

func requestMAC(key []byte, path string, body []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(peerReqLabel))
	m.Write([]byte(path))
	m.Write([]byte{0})
	m.Write(body)
	return m.Sum(nil)
}

func answerMAC(key, reqBody, body []byte) []byte {
	sum := sha256.Sum256(reqBody)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(peerAnsLabel))
	m.Write(sum[:])
	m.Write(body)
	return m.Sum(nil)
}

// peerKey is the MAC key, or nil before this vault holds a generation
// keyset.
func (s *Server) peerKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerMAC
}

// handlePeer serves /register/head and /register/apply to other vaults.
func (s *Server) handlePeer(w http.ResponseWriter, r *http.Request) {
	key := s.peerKey()
	if key == nil {
		writeError(w, http.StatusConflict, errNoGeneration)
		return
	}
	var env envelope
	if !decode(w, r, maxPeerBody, &env) {
		return
	}
	if !hmac.Equal(env.MAC, requestMAC(key, r.URL.Path, env.Body)) {
		s.refuse(w, "register", errors.New("not from a vault holding the generation keyset"))
		return
	}
	var req peerRequest
	if err := json.Unmarshal(env.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ans := peerAnswer{Instance: s.instance}
	if r.URL.Path == pathApply {
		result, err := s.reg.apply(req.Chain)
		if err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		ans.Result = result
	}
	ans.History = s.reg.snapshot()
	body, err := json.Marshal(ans)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, envelope{Body: body, MAC: answerMAC(key, env.Body, body)})
}

// peerCall makes one MACed call to the vault at host and checks its answer.
func (s *Server) peerCall(ctx context.Context, host, path string, chain []regState) (*peerAnswer, error) {
	key := s.peerKey()
	if key == nil {
		return nil, errNoGeneration
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	reqBody, err := json.Marshal(peerRequest{Nonce: hex.EncodeToString(nonce), Chain: chain})
	if err != nil {
		return nil, err
	}
	in, err := json.Marshal(envelope{Body: reqBody, MAC: requestMAC(key, path, reqBody)})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, peerCallTimout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.peerBase(host)+path, bytes.NewReader(in))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxPeerBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s%s answered %d: %.300s", host, path, resp.StatusCode, raw)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if !hmac.Equal(env.MAC, answerMAC(key, reqBody, env.Body)) {
		return nil, fmt.Errorf("%s%s: the answer isn't from a vault holding the generation keyset", host, path)
	}
	var ans peerAnswer
	if err := json.Unmarshal(env.Body, &ans); err != nil {
		return nil, err
	}
	if len(ans.History) == 0 {
		return nil, fmt.Errorf("%s holds no register", host)
	}
	if err := validChain(ans.History); err != nil {
		return nil, fmt.Errorf("%s's register: %w", host, err)
	}
	return &ans, nil
}

// view is one vault's register, as read for a call.
type view struct {
	host     string
	instance string
	history  []regState
}

func (v *view) head() regState { return v.history[len(v.history)-1] }

// readBoth reads both vaults' registers, in VAULT_PEERS order.
func (s *Server) readBoth(ctx context.Context) ([]*view, error) {
	views := make([]*view, len(s.cfg.Peers))
	errs := make([]error, len(s.cfg.Peers))
	var wg sync.WaitGroup
	for i, host := range s.cfg.Peers {
		wg.Go(func() {
			ans, err := s.peerCall(ctx, host, pathHead, nil)
			if err != nil {
				errs[i] = err
				return
			}
			views[i] = &view{host: host, instance: ans.Instance, history: ans.History}
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("%w: %w", errRegisterUnavailable, err)
	}
	if views[0].instance == views[1].instance {
		return nil, fmt.Errorf("%w: %s and %s answered from one vault", errRegisterUnavailable, views[0].host, views[1].host)
	}
	return views, nil
}

// settle reads both vaults and brings the one behind up to the other. It
// returns the head both hold, and what it read.
func (s *Server) settle(ctx context.Context) (regState, []*view, error) {
	views, err := s.readBoth(ctx)
	if err != nil {
		return regState{}, nil, err
	}
	a, b := views[0], views[1]
	if a.head().hash() == b.head().hash() {
		s.adopt(a.history)
		return a.head(), views, nil
	}
	lead, lag := a, b
	if b.head().Version > a.head().Version {
		lead, lag = b, a
	}
	if lead.head().Version == lag.head().Version {
		return regState{}, nil, fmt.Errorf("%w: both at version %d with different states", errDiverged, lead.head().Version)
	}
	chain := fromHistory(lead.history, lag.head())
	if chain == nil {
		return regState{}, nil, fmt.Errorf("%w: %s at version %d isn't in %s's history to version %d", errDiverged, lag.host, lag.head().Version, lead.host, lead.head().Version)
	}
	ans, err := s.peerCall(ctx, lag.host, pathApply, chain)
	if err != nil {
		return regState{}, nil, fmt.Errorf("%w: bringing %s up: %w", errRegisterUnavailable, lag.host, err)
	}
	if ans.Instance != lag.instance || ans.Result != resultAccepted {
		return regState{}, nil, fmt.Errorf("%w: %s didn't take %s's register", errLostRace, lag.host, lead.host)
	}
	log.Printf("register: brought %s from version %d to %d", lag.host, lag.head().Version, lead.head().Version)
	lag.history = ans.History
	s.adopt(lead.history)
	return lead.head(), views, nil
}

// adopt brings this vault's own copy up when it's behind: a vault held as
// an upgrade candidate isn't one of the two hosts until it's promoted.
func (s *Server) adopt(history []regState) {
	if _, err := s.reg.apply(history); err != nil {
		log.Printf("register: keeping this vault's copy: %v", err)
	}
}

// propose makes one change: next decides it from the head both vaults
// hold, or returns nil for none. The change goes to the first vault, then
// the second, and is returned once both hold it.
func (s *Server) propose(ctx context.Context, next func(head regState) (*regState, error)) (regState, error) {
	s.proposeMu.Lock()
	defer s.proposeMu.Unlock()
	head, views, err := s.settle(ctx)
	if err != nil {
		return regState{}, fmt.Errorf("%w: %w", errNothingMoved, err)
	}
	n, err := next(head)
	if err != nil || n == nil {
		return head, err
	}
	chain := []regState{head, *n}
	if err := validChain(chain); err != nil {
		return regState{}, err
	}
	for _, v := range views {
		ans, err := s.peerCall(ctx, v.host, pathApply, chain)
		if err != nil {
			return regState{}, fmt.Errorf("%w: %s: %w", errRegisterUnavailable, v.host, err)
		}
		if ans.Instance != v.instance {
			return regState{}, fmt.Errorf("%w: %s restarted mid-change", errRegisterUnavailable, v.host)
		}
		if ans.Result != resultAccepted {
			return regState{}, fmt.Errorf("%w (at %s)", errLostRace, v.host)
		}
	}
	s.adopt(chain)
	return *n, nil
}

// errNothingMoved is a proposal refused before it was sent to either vault.
var errNothingMoved = errors.New("nothing changed")

// syncLoop keeps both vaults' registers level, and this vault's own copy
// with them, so a vault promoted from a held candidate is current within
// seconds.
func (s *Server) syncLoop(ctx context.Context) {
	for ctx.Err() == nil {
		if s.peerKey() != nil {
			_, _, err := s.settle(ctx)
			s.recordSync(err)
			if err != nil {
				log.Printf("register sync: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(syncEvery):
		}
	}
}

type syncRecord struct {
	At    time.Time `json:"at"`
	Error string    `json:"error,omitempty"`
}

func (s *Server) recordSync(err error) {
	rec := &syncRecord{At: time.Now().UTC()}
	if err != nil {
		rec.Error = fmt.Sprintf("%.300v", err)
	}
	s.mu.Lock()
	s.lastSync = rec
	s.mu.Unlock()
}

// registerStatus is what /status shows of the register.
func (s *Server) registerStatus() map[string]any {
	head, ok := s.reg.head()
	if !ok {
		return nil
	}
	return map[string]any{
		"version":    head.Version,
		"head":       head.hash()[:16],
		"generation": head.Generation,
		"count":      head.Count,
		"booted":     len(head.Key) != 0,
	}
}
