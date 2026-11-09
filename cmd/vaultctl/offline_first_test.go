package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/fount-labs/fount-mail-vault/internal/opclient"
	"github.com/fount-labs/fount-mail-vault/internal/recovery"
	"github.com/fount-labs/fount-mail-vault/internal/vault"
	"github.com/fount-labs/fount-mail-vault/wire"
)

// fakeVault answers /operator/begin and /recovery/share like an empty vault, and
// opens each sealed share to check it's the one the bundle holds.
type fakeVault struct {
	t     *testing.T
	key   *ecdh.PrivateKey
	want  []byte
	mu    sync.Mutex
	paths []string
	issue []byte
}

func (f *fakeVault) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()
	switch r.URL.Path {
	case "/operator/begin":
		var req vault.OperatorBeginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(vault.OperatorBeginResponse{
			Nonce:    hex.EncodeToString(f.issue),
			Document: []byte("doc:" + req.AnswerNonce),
			VaultKey: f.key.PublicKey().Bytes(),
		})
	case "/recovery/share":
		var req vault.SealedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		answer, err := wire.DecodeNonce(req.AnswerNonce)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sender, err := wire.ParseRawKey(req.SenderKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got, err := wire.Open(wire.PurposeShare, f.key, sender, wire.Nonces{Issued: f.issue, Answer: answer}, req.Sealed)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !bytes.Equal(got, f.want) {
			f.t.Errorf("vault opened a share that isn't the bundle's")
		}
		json.NewEncoder(w).Encode(map[string]bool{"restored": true})
	default:
		http.NotFound(w, r)
	}
}

// drillFixture writes a throwaway identity and a one-of-one bundle for it, and
// starts a fake vault that expects that bundle's share.
func drillFixture(t *testing.T) (bundlePath, identityPath string, fv *fakeVault, c *opclient.Client) {
	t.Helper()
	dir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	identityPath = filepath.Join(dir, "id.txt")
	if err := os.WriteFile(identityPath, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := wire.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := recovery.NewBundle(k, []string{id.Recipient().String()}, 1)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath = filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	shares, err := b.Decrypt([]age.Identity{id})
	if err != nil || len(shares) != 1 {
		t.Fatalf("decrypt fixture: %d shares, %v", len(shares), err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issue, err := wire.RandomNonce()
	if err != nil {
		t.Fatal(err)
	}
	fv = &fakeVault{t: t, key: key, want: shares[0], issue: issue}
	srv := httptest.NewServer(fv)
	t.Cleanup(srv.Close)
	c = &opclient.Client{HTTP: srv.Client(), Base: srv.URL, Verify: func(doc, nonce []byte) (*ecdh.PublicKey, error) {
		if string(doc) != "doc:"+hex.EncodeToString(nonce) {
			return nil, errors.New("document isn't for this nonce")
		}
		return key.PublicKey(), nil
	}}
	return bundlePath, identityPath, fv, c
}

// promptWatcher records the prompt and signals once it's been printed in full.
type promptWatcher struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	printed chan struct{}
	once    sync.Once
}

func (p *promptWatcher) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buf.Write(b)
	if strings.Contains(p.buf.String(), offlinePrompt+": ") {
		p.once.Do(func() { close(p.printed) })
	}
	return len(b), nil
}

func TestOfflineFirstNoNetworkBeforeEnter(t *testing.T) {
	bundlePath, identityPath, fv, c := drillFixture(t)
	stdin, typed := io.Pipe()
	prompt := &promptWatcher{printed: make(chan struct{})}
	gate := func(opened int) error { return waitForEnter(stdin, prompt, opened) }

	done := make(chan error, 1)
	go func() { done <- submitShare(context.Background(), c, bundlePath, []string{identityPath}, gate) }()

	select {
	case <-prompt.printed:
	case err := <-done:
		t.Fatalf("returned before prompting: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no prompt")
	}
	time.Sleep(50 * time.Millisecond)
	if got := fv.requests(); len(got) != 0 {
		t.Fatalf("network calls before Enter: %v", got)
	}
	if !strings.Contains(prompt.buf.String(), "opened 1 share(s)") {
		t.Fatalf("prompt = %q", prompt.buf.String())
	}

	if _, err := typed.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("didn't finish after Enter")
	}
	if got := fv.requests(); strings.Join(got, " ") != "/operator/begin /recovery/share" {
		t.Fatalf("requests after Enter = %v", got)
	}
}

func TestOfflineFirstEOFSendsNothing(t *testing.T) {
	bundlePath, identityPath, fv, c := drillFixture(t)
	var prompt bytes.Buffer
	gate := func(opened int) error { return waitForEnter(strings.NewReader("no newline"), &prompt, opened) }
	err := submitShare(context.Background(), c, bundlePath, []string{identityPath}, gate)
	if err == nil || !strings.Contains(err.Error(), "nothing was sent") {
		t.Fatalf("err = %v, want an abort", err)
	}
	if got := fv.requests(); len(got) != 0 {
		t.Fatalf("network calls without Enter: %v", got)
	}
}

func TestOfflineFirstWrongIdentityFailsBeforePrompt(t *testing.T) {
	bundlePath, _, fv, c := drillFixture(t)
	_, otherIdentity, _, _ := drillFixture(t)
	prompted := false
	gate := func(int) error { prompted = true; return nil }
	err := submitShare(context.Background(), c, bundlePath, []string{otherIdentity}, gate)
	if err == nil {
		t.Fatal("a stranger's identity submitted a share")
	}
	if prompted {
		t.Fatal("prompted although no share opened")
	}
	if got := fv.requests(); len(got) != 0 {
		t.Fatalf("network calls: %v", got)
	}
}

func TestSubmitShareWithoutGateStillSends(t *testing.T) {
	bundlePath, identityPath, fv, c := drillFixture(t)
	if err := submitShare(context.Background(), c, bundlePath, []string{identityPath}, nil); err != nil {
		t.Fatal(err)
	}
	if got := fv.requests(); strings.Join(got, " ") != "/operator/begin /recovery/share" {
		t.Fatalf("requests = %v", got)
	}
}
