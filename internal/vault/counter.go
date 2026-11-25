package vault

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/fount-labs/fount-mail-vault/wire"
)

// The Cloud vault's generation and counter (docs/COORDINATOR-COUNTER.md).

const (
	maxCounterCalls   = 16
	loadSettleTimeout = 30 * time.Second
)

var errNotCloud = errors.New("this vault isn't a Cloud vault (COORDINATOR_MODE)")

// generation is the held generation keyset, or nil.
func (s *Server) generation() *wire.GenerationKeyset {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.genKeyset
}

// committedGeneration is the generation keyset this release commits to, or
// an error saying why there's none to sign with: only a release with
// GENERATION_AUTHORITY_KEY boots generations or answers the counter, since
// a coordinator checks every answer against that key.
func (s *Server) committedGeneration() (*wire.GenerationKeyset, error) {
	switch {
	case !s.cfg.CoordinatorMode:
		return nil, errNotCloud
	case s.cfg.GenerationKey == "":
		return nil, errors.New("this release commits to no generation keyset (GENERATION_AUTHORITY_KEY)")
	}
	g := s.generation()
	if g == nil {
		return nil, errNoGeneration
	}
	return g, nil
}

// installGeneration keeps the first generation keyset, with the register
// that came with it. It reports whether it installed them.
func (s *Server) installGeneration(g *wire.GenerationKeyset, history []regState, source string) (bool, error) {
	if !s.cfg.CoordinatorMode || g == nil {
		return false, nil
	}
	if s.cfg.GenerationKey != "" && !g.Matches(s.cfg.GenerationKey) {
		return false, fmt.Errorf("generation keyset %s isn't GENERATION_AUTHORITY_KEY", g.AuthorityKey())
	}
	if err := validChain(history); err != nil {
		return false, fmt.Errorf("the register that came with the generation keyset: %w", err)
	}
	if err := s.cfg.checkFloors(history[len(history)-1]); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.genKeyset != nil {
		return false, nil
	}
	if !s.reg.install(history) {
		return false, errors.New("this vault holds a register and no generation keyset")
	}
	s.genKeyset, s.genSource = g, source
	s.peerMAC = peerMACKey(g.Seed[:])
	return true, nil
}

// handleGenerateGeneration works once, in a Cloud release with a keyset
// commitment and no GENERATION_AUTHORITY_KEY, on a vault holding the keyset.
// It starts the register at the release's floors. Anyone may call it: the
// seed never leaves the enclave except to a verified vault.
func (s *Server) handleGenerateGeneration(w http.ResponseWriter, _ *http.Request) {
	switch {
	case !s.cfg.CoordinatorMode:
		writeError(w, http.StatusConflict, errNotCloud)
		return
	case s.cfg.GenerationKey != "":
		writeError(w, http.StatusConflict, errors.New("this release commits to a generation keyset, so it can't generate one"))
		return
	case s.cfg.Commitment == "":
		writeError(w, http.StatusConflict, errors.New("this release has no keyset commitment, so it can't generate a generation keyset"))
		return
	case !s.holds():
		writeError(w, http.StatusConflict, errNoKeyset)
		return
	case s.generation() != nil:
		writeError(w, http.StatusConflict, errors.New("this vault already holds a generation keyset"))
		return
	}
	g, err := wire.GenerateGenerationKeyset()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	genesis := regState{Generation: s.cfg.GenerationFloor, Count: s.cfg.CountFloor}
	installed, err := s.installGeneration(g, []regState{genesis}, "generated")
	if err != nil || !installed {
		writeError(w, http.StatusConflict, errors.Join(errors.New("this vault already holds a generation keyset"), err))
		return
	}
	log.Printf("generated generation keyset %s; register at generation %d, count %d", g.AuthorityKey(), genesis.Generation, genesis.Count)
	writeJSON(w, http.StatusOK, map[string]any{"authority_key": g.AuthorityKey(), "generation": genesis.Generation, "count": genesis.Count})
}

// boot moves the generation on for a coordinator's per-boot key, keeping
// the count, and certifies the new generation. The certificate is signed
// only once both vaults hold the new generation.
func (s *Server) boot(ctx context.Context, key ed25519.PublicKey) (string, uint64, error) {
	g, err := s.committedGeneration()
	if err != nil {
		return "", 0, err
	}
	committed, err := s.propose(ctx, func(head regState) (*regState, error) {
		return &regState{Version: head.Version + 1, Prev: head.hash(), Generation: head.Generation + 1, Key: key, Count: head.Count,
			Digest: head.Digest, Writer: head.Writer}, nil
	})
	if err != nil {
		return "", 0, err
	}
	cert, err := wire.SignGenerationCertificate(g.Authority(), wire.GenerationCertificate{
		Generation: committed.Generation, CoordinatorKey: key, IssuedAt: time.Now().Unix()})
	if err != nil {
		return "", 0, err
	}
	log.Printf("booted coordinator generation %d for key %x, count %d", committed.Generation, key[:8], committed.Count)
	return cert, committed.Generation, nil
}

// handleCounter is POST /coordinator/counter. Anything it means is signed;
// a vault it can't reach, or a register it can't settle, is an unsigned
// 503, which the coordinator retries.
func (s *Server) handleCounter(w http.ResponseWriter, r *http.Request) {
	g, err := s.committedGeneration()
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}
	var req wire.CounterRequest
	if !decode(w, r, wire.MaxCounterBody, &req) {
		return
	}
	nonce, err := req.Validate()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// A load is unauthenticated, so loads share settles rather than slots:
	// a flood of them can't take the slots a swap needs (review L4).
	if req.Op == wire.CounterCAS {
		select {
		case s.counterCalls <- struct{}{}:
			defer func() { <-s.counterCalls }()
		default:
			writeError(w, http.StatusTooManyRequests, errTooMany)
			return
		}
	}
	var (
		result string
		st     wire.CounterState
	)
	switch req.Op {
	case wire.CounterLoad:
		head, err := s.sharedSettle(r.Context())
		if err != nil {
			s.unavailable(w, err)
			return
		}
		result, st = wire.CounterOK, head.counterState()
	case wire.CounterCAS:
		_, err := s.propose(r.Context(), func(head regState) (*regState, error) {
			st = head.counterState()
			msg := wire.CASMessage(nonce, req.Generation, req.Prev, req.Next)
			var writer uint64
			if req.Version == 2 {
				msg, writer = wire.CASMessageV2(nonce, req.Generation, req.Prev, req.Next, req.StateDigest), req.Generation
			}
			switch {
			case req.Generation != head.Generation:
				result = wire.CounterStaleGeneration
			case len(head.Key) != ed25519.PublicKeySize:
				result = wire.CounterNoGeneration
			case !ed25519.Verify(head.Key, msg, req.Signature):
				result = wire.CounterBadSignature
			case head.Count == req.Next && head.Swap != nil && *head.Swap == (regSwap{req.Generation, req.Prev, req.Next}) &&
				head.Digest == req.StateDigest && head.Writer == writer:
				// A retry after a lost answer: this swap is the last one made.
				result = wire.CounterOK
			case head.Count != req.Prev || req.Next <= req.Prev:
				result = wire.CounterCountMismatch
			default:
				n := &regState{Version: head.Version + 1, Prev: head.hash(), Generation: head.Generation, Key: head.Key,
					Count: req.Next, Swap: &regSwap{req.Generation, req.Prev, req.Next}, Digest: req.StateDigest, Writer: writer}
				result, st = wire.CounterOK, n.counterState()
				return n, nil
			}
			return nil, nil
		})
		if err != nil {
			s.unavailable(w, err)
			return
		}
	}
	status := http.StatusOK
	if result != wire.CounterOK {
		status = http.StatusConflict
	}
	writeJSON(w, status, wire.AnswerCounter(g.Authority(), &req, result, st))
}

// loadFlight is one settle that loads share.
type loadFlight struct {
	done chan struct{}
	head regState
	err  error
}

// sharedSettle is settle for a load. Every load that arrives while a settle
// runs waits for the next one, which starts after they all arrived, so each
// still sees a head at least as new as its own arrival; at most two settles
// for loads run at once, however many loads come.
func (s *Server) sharedSettle(ctx context.Context) (regState, error) {
	s.loadMu.Lock()
	if s.loadNext == nil {
		s.loadNext = &loadFlight{done: make(chan struct{})}
	}
	f := s.loadNext
	if !s.loadRunning {
		s.startLoadLocked()
	}
	s.loadMu.Unlock()
	select {
	case <-f.done:
		return f.head, f.err
	case <-ctx.Done():
		return regState{}, ctx.Err()
	}
}

// startLoadLocked runs loadNext. Called with loadMu held.
func (s *Server) startLoadLocked() {
	f := s.loadNext
	s.loadNext, s.loadRunning = nil, true
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), loadSettleTimeout)
		f.head, _, f.err = s.settle(ctx)
		cancel()
		close(f.done)
		s.loadMu.Lock()
		s.loadRunning = false
		if s.loadNext != nil {
			s.startLoadLocked()
		}
		s.loadMu.Unlock()
	}()
}

func (h regState) counterState() wire.CounterState {
	return wire.CounterState{Generation: h.Generation, Count: h.Count, StateDigest: h.Digest, Writer: h.Writer}
}

func (s *Server) unavailable(w http.ResponseWriter, err error) {
	log.Printf("counter: %v", err)
	writeError(w, http.StatusServiceUnavailable, err)
}
