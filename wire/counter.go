package wire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// The coordinator's counter (docs/COORDINATOR-COUNTER.md): POST
// /coordinator/counter on either Cloud vault. A load is unauthenticated. A
// cas is signed by the key the current generation's certificate names. Every
// answer the vault means, refusals included, is signed by the generation
// authority over the request's digest, which covers the caller's fresh
// nonce, so an answer can't be replayed to another request or forged by the
// network. Anything unsigned is the vault being unavailable.

const CounterPath = "/coordinator/counter"

// Counter operations.
const (
	CounterLoad = "load"
	CounterCAS  = "cas"
)

// Counter results. Every one is signed.
const (
	CounterOK = "ok"
	// CounterStaleGeneration: the generation named isn't the current one.
	CounterStaleGeneration = "stale_generation"
	// CounterCountMismatch: the count isn't prev (and this isn't a retry of
	// the last swap), or next isn't above prev.
	CounterCountMismatch = "count_mismatch"
	// CounterBadSignature: the generation is current and the cas isn't
	// signed by its key.
	CounterBadSignature = "bad_signature"
	// CounterNoGeneration: no coordinator has booted since the register
	// began, so nothing may swap.
	CounterNoGeneration = "no_generation"
)

// MaxCount and MaxCountStep bound a swap. The coordinator's security sequence
// moves by one, so a swap that jumps further is a bug or an attacker; a count
// at 2^64-1 would leave no successor, and one at 2^63 or more couldn't be
// written back as COUNT_FLOOR after a total loss (security review M4).
const (
	MaxCount     = 1<<63 - 1
	MaxCountStep = 1 << 20
)

// MaxCounterBody bounds a counter request or answer.
const MaxCounterBody = 4 << 10

// CounterRequest is the body of POST /coordinator/counter.
type CounterRequest struct {
	Op    string `json:"op"`
	Nonce string `json:"nonce"` // hex, NonceSize bytes, fresh per request
	// Generation, Prev and Next are a cas's; zero for a load.
	Generation uint64 `json:"generation,omitempty"`
	Prev       uint64 `json:"prev,omitempty"`
	Next       uint64 `json:"next,omitempty"`
	// Signature is a cas's, by the generation's key over CASMessage, or
	// CASMessageV2 at version 2.
	Signature []byte `json:"signature,omitempty"`
	// Version 2 binds the count to a state (broker review H2): a cas
	// carries StateDigest, the digest of the coordinator state the new
	// count counts, and the answer carries the counted state's digest and
	// the generation that wrote it. 0 is version 1, which a vault that
	// predates version 2 answers, and which never sees a digest.
	Version     int    `json:"v,omitempty"`
	StateDigest string `json:"state_digest,omitempty"` // hex, StateDigestSize bytes
}

// CounterAnswer is the vault's answer, at 200 for ok and 409 for a refusal.
type CounterAnswer struct {
	Result     string `json:"result"`
	Generation uint64 `json:"generation"`
	Count      uint64 `json:"count"`
	// StateDigest and Writer are the counted state's, at version 2.
	StateDigest string `json:"state_digest,omitempty"`
	Writer      uint64 `json:"writer,omitempty"`
	// Signature is the authority's over CounterAnswerMessage.
	Signature []byte `json:"signature"`
}

// CounterState is what the register holds that a coordinator sees.
type CounterState struct {
	Generation uint64 `json:"generation"`
	Count      uint64 `json:"count"`
	// StateDigest is the digest of the state the count counts, and Writer
	// the generation whose cas set it: empty and 0 for a count no version
	// 2 cas has set, such as a register at its floors. Version 2 only. Hex.
	StateDigest string `json:"state_digest,omitempty"`
	Writer      uint64 `json:"writer,omitempty"`
}

const (
	counterRequestLabel  = "fount-coordinator-counter/v1/request\x00"
	counterCASLabel      = "fount-coordinator-counter/v1/cas\x00"
	counterAnswerLabel   = "fount-coordinator-counter/v1/answer\x00"
	counterCASLabelV2    = "fount-coordinator-counter/v2/cas\x00"
	counterAnswerLabelV2 = "fount-coordinator-counter/v2/answer\x00"
)

// StateDigestSize is a version 2 cas's StateDigest length, before hex.
const StateDigestSize = 32

// ValidStateDigest is whether d is a state digest: lowercase hex of
// StateDigestSize bytes.
func ValidStateDigest(d string) bool {
	raw, err := hex.DecodeString(d)
	return err == nil && len(raw) == StateDigestSize && hex.EncodeToString(raw) == d
}

// Validate checks the shape and returns the nonce.
func (r *CounterRequest) Validate() ([]byte, error) {
	nonce, err := DecodeNonce(r.Nonce)
	if err != nil {
		return nil, err
	}
	switch {
	case r.Version != 0 && r.Version != 2:
		return nil, fmt.Errorf("unknown counter version %d", r.Version)
	case len(r.StateDigest) != 0 && (r.Version != 2 || r.Op != CounterCAS):
		return nil, errors.New("only a version 2 cas carries a state digest")
	case r.Version == 2 && r.Op == CounterCAS && !ValidStateDigest(r.StateDigest):
		return nil, fmt.Errorf("a version 2 cas carries a %d-byte hex state digest", StateDigestSize)
	}
	switch r.Op {
	case CounterLoad:
		if r.Generation != 0 || r.Prev != 0 || r.Next != 0 || len(r.Signature) != 0 {
			return nil, errors.New("a load carries only a nonce")
		}
	case CounterCAS:
		if r.Generation == 0 || len(r.Signature) != ed25519.SignatureSize {
			return nil, errors.New("a cas names a generation and is signed")
		}
		if r.Next > MaxCount || (r.Next > r.Prev && r.Next-r.Prev > MaxCountStep) {
			return nil, fmt.Errorf("a cas moves the count by at most %d, to at most %d", MaxCountStep, uint64(MaxCount))
		}
	default:
		return nil, fmt.Errorf("unknown counter op %q", r.Op)
	}
	return nonce, nil
}

// Digest is what an answer is bound to. Call Validate first.
func (r *CounterRequest) Digest() [32]byte {
	nonce, _ := hex.DecodeString(r.Nonce)
	h := sha256.New()
	h.Write([]byte(counterRequestLabel))
	h.Write([]byte(r.Op))
	h.Write([]byte{0})
	h.Write(nonce)
	h.Write(be64(r.Generation))
	h.Write(be64(r.Prev))
	h.Write(be64(r.Next))
	if r.Version == 2 {
		d, _ := hex.DecodeString(r.StateDigest)
		h.Write([]byte{2, byte(len(d))})
		h.Write(d)
	}
	var d [32]byte
	h.Sum(d[:0])
	return d
}

// CASMessage is what a generation's key signs for a cas. Its label keeps it
// from passing for an edge request, which starts with the method.
func CASMessage(nonce []byte, generation, prev, next uint64) []byte {
	msg := []byte(counterCASLabel)
	msg = append(msg, nonce...)
	msg = append(msg, be64(generation)...)
	msg = append(msg, be64(prev)...)
	return append(msg, be64(next)...)
}

// CASMessageV2 is CASMessage for a version 2 cas: it signs the state digest
// too, so nobody between the coordinator and the vault can swap it.
func CASMessageV2(nonce []byte, generation, prev, next uint64, digest string) []byte {
	msg := []byte(counterCASLabelV2)
	msg = append(msg, nonce...)
	msg = append(msg, be64(generation)...)
	msg = append(msg, be64(prev)...)
	msg = append(msg, be64(next)...)
	d, _ := hex.DecodeString(digest)
	return append(msg, d...)
}

// CounterAnswerMessageV2 is CounterAnswerMessage for a version 2 request:
// the counted state's digest and writer are signed too.
func CounterAnswerMessageV2(digest [32]byte, result string, st CounterState) []byte {
	msg := []byte(counterAnswerLabelV2)
	msg = append(msg, digest[:]...)
	msg = append(msg, result...)
	msg = append(msg, 0)
	msg = append(msg, be64(st.Generation)...)
	msg = append(msg, be64(st.Count)...)
	d, _ := hex.DecodeString(st.StateDigest)
	msg = append(msg, byte(len(d)))
	msg = append(msg, d...)
	return append(msg, be64(st.Writer)...)
}

func answerMessage(r *CounterRequest, result string, st CounterState) []byte {
	if r.Version == 2 {
		return CounterAnswerMessageV2(r.Digest(), result, st)
	}
	return CounterAnswerMessage(r.Digest(), result, CounterState{Generation: st.Generation, Count: st.Count})
}

// CounterAnswerMessage is what the authority signs for an answer.
func CounterAnswerMessage(digest [32]byte, result string, st CounterState) []byte {
	msg := []byte(counterAnswerLabel)
	msg = append(msg, digest[:]...)
	msg = append(msg, result...)
	msg = append(msg, 0)
	msg = append(msg, be64(st.Generation)...)
	return append(msg, be64(st.Count)...)
}

// AnswerCounter signs an answer to r. A version 1 request gets no digest or
// writer.
func AnswerCounter(authority ed25519.PrivateKey, r *CounterRequest, result string, st CounterState) CounterAnswer {
	a := CounterAnswer{Result: result, Generation: st.Generation, Count: st.Count}
	if r.Version == 2 {
		a.StateDigest, a.Writer = st.StateDigest, st.Writer
	}
	a.Signature = ed25519.Sign(authority, answerMessage(r, result, st))
	return a
}

func knownResult(r string) bool {
	switch r {
	case CounterOK, CounterStaleGeneration, CounterCountMismatch, CounterBadSignature, CounterNoGeneration:
		return true
	}
	return false
}

// VerifyCounterAnswer checks that a answers r, signed by authority.
func VerifyCounterAnswer(authority ed25519.PublicKey, r *CounterRequest, a *CounterAnswer) error {
	if !knownResult(a.Result) {
		return fmt.Errorf("unknown counter result %q", a.Result)
	}
	st := a.state(r)
	if st.StateDigest != "" && !ValidStateDigest(st.StateDigest) {
		return errors.New("the counter's answer carries a malformed state digest")
	}
	if !ed25519.Verify(authority, answerMessage(r, a.Result, st), a.Signature) {
		return errors.New("the counter's answer isn't signed by the generation authority for this request")
	}
	return nil
}

// state is what a verified answer to r says.
func (a *CounterAnswer) state(r *CounterRequest) CounterState {
	st := CounterState{Generation: a.Generation, Count: a.Count}
	if r.Version == 2 {
		st.StateDigest, st.Writer = a.StateDigest, a.Writer
	}
	return st
}

func be64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

var (
	// ErrCounterGeneration: the vault has moved to another generation, or
	// this one's key isn't the caller's. The caller must stop.
	ErrCounterGeneration = errors.New("the vault's counter is at another coordinator generation")
	// ErrCounterCount: the count isn't where the caller left it.
	ErrCounterCount = errors.New("the vault's counter isn't at the count named")
	// ErrCounterUnavailable: no vault gave a signed answer.
	ErrCounterUnavailable = errors.New("no vault gave a signed counter answer")
)

// CounterRefusal is a signed refusal. It matches ErrCounterGeneration or
// ErrCounterCount.
type CounterRefusal struct {
	Result string
	State  CounterState
}

func (e *CounterRefusal) Error() string {
	return fmt.Sprintf("the vault's counter refused: %s (generation %d, count %d)", e.Result, e.State.Generation, e.State.Count)
}

func (e *CounterRefusal) Unwrap() error {
	if e.Result == CounterCountMismatch {
		return ErrCounterCount
	}
	return ErrCounterGeneration
}

// CounterClient calls the counter on Vaults, origins such as
// https://vault-a.example, in order, until one gives a signed answer.
type CounterClient struct {
	Vaults    []string
	Authority ed25519.PublicKey
	Client    *http.Client
}

// Load is the current generation and count.
func (c *CounterClient) Load(ctx context.Context) (CounterState, error) {
	nonce, err := RandomNonce()
	if err != nil {
		return CounterState{}, err
	}
	return c.call(ctx, &CounterRequest{Op: CounterLoad, Nonce: hex.EncodeToString(nonce)})
}

// CompareAndSwap moves the count from prev to next under generation, whose
// key is key. A retry after a lost answer succeeds.
func (c *CounterClient) CompareAndSwap(ctx context.Context, key ed25519.PrivateKey, generation, prev, next uint64) (CounterState, error) {
	if len(key) != ed25519.PrivateKeySize {
		return CounterState{}, errors.New("a cas needs the generation's key")
	}
	nonce, err := RandomNonce()
	if err != nil {
		return CounterState{}, err
	}
	r := &CounterRequest{Op: CounterCAS, Nonce: hex.EncodeToString(nonce), Generation: generation, Prev: prev, Next: next,
		Signature: ed25519.Sign(key, CASMessage(nonce, generation, prev, next))}
	if _, err := r.Validate(); err != nil {
		return CounterState{}, err
	}
	st, err := c.call(ctx, r)
	if err != nil {
		return st, err
	}
	if st.Generation != generation || st.Count != next {
		return st, fmt.Errorf("the vault answered ok with generation %d and count %d to a cas to %d under %d", st.Generation, st.Count, next, generation)
	}
	return st, nil
}

// LoadState is Load at version 2: the count, the digest of the state it
// counts and the generation that wrote it. It needs a vault with version 2;
// an older one's answer doesn't verify.
func (c *CounterClient) LoadState(ctx context.Context) (CounterState, error) {
	nonce, err := RandomNonce()
	if err != nil {
		return CounterState{}, err
	}
	return c.call(ctx, &CounterRequest{Op: CounterLoad, Nonce: hex.EncodeToString(nonce), Version: 2})
}

// CompareAndSwapState is CompareAndSwap at version 2: next counts the state
// whose digest is digest. A retry after a lost answer succeeds only with the
// same digest.
func (c *CounterClient) CompareAndSwapState(ctx context.Context, key ed25519.PrivateKey, generation, prev, next uint64, digest string) (CounterState, error) {
	if len(key) != ed25519.PrivateKeySize {
		return CounterState{}, errors.New("a cas needs the generation's key")
	}
	nonce, err := RandomNonce()
	if err != nil {
		return CounterState{}, err
	}
	r := &CounterRequest{Op: CounterCAS, Nonce: hex.EncodeToString(nonce), Generation: generation, Prev: prev, Next: next,
		Version: 2, StateDigest: digest, Signature: ed25519.Sign(key, CASMessageV2(nonce, generation, prev, next, digest))}
	if _, err := r.Validate(); err != nil {
		return CounterState{}, err
	}
	st, err := c.call(ctx, r)
	if err != nil {
		return st, err
	}
	if st.Generation != generation || st.Count != next || st.StateDigest != digest || st.Writer != generation {
		return st, fmt.Errorf("the vault answered ok with generation %d, count %d and another state to a cas to %d under %d", st.Generation, st.Count, next, generation)
	}
	return st, nil
}

func (c *CounterClient) call(ctx context.Context, r *CounterRequest) (CounterState, error) {
	if len(c.Vaults) == 0 || len(c.Authority) != ed25519.PublicKeySize || c.Client == nil {
		return CounterState{}, errors.New("a counter client needs vaults, the authority key and a client")
	}
	body, err := json.Marshal(r)
	if err != nil {
		return CounterState{}, err
	}
	var errs []error
	for _, base := range c.Vaults {
		a, err := c.post(ctx, base+CounterPath, body)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", base, err))
			continue
		}
		if err := VerifyCounterAnswer(c.Authority, r, a); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", base, err))
			continue
		}
		st := a.state(r)
		if a.Result != CounterOK {
			return st, &CounterRefusal{Result: a.Result, State: st}
		}
		return st, nil
	}
	return CounterState{}, fmt.Errorf("%w: %w", ErrCounterUnavailable, errors.Join(errs...))
}

// post returns the answer at 200 or 409; any other status is the vault
// being unavailable.
func (c *CounterClient) post(ctx context.Context, url string, body []byte) (*CounterAnswer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxCounterBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusConflict {
		return nil, fmt.Errorf("answered %d: %.300s", resp.StatusCode, raw)
	}
	var a CounterAnswer
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("decoding the answer: %w", err)
	}
	return &a, nil
}
