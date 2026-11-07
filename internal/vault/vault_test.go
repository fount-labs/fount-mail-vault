package vault_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/fount-labs/fount-mail-vault/internal/attest"
	"github.com/fount-labs/fount-mail-vault/internal/opclient"
	"github.com/fount-labs/fount-mail-vault/internal/vault"
	"github.com/fount-labs/fount-mail-vault/wire"
)

const (
	vaultRepo = "fount-labs/fount-mail-vault"
	edgeRepo  = "fount-labs/fount-mail-edge"
)

// world stands in for hardware and provenance. A document is the enclave's name
// and the nonce, and it verifies against a pin only if that name was released
// from the pinned repo.
type world struct {
	releases map[string]map[string]release // pin, then name
}

type release struct {
	key *ecdh.PublicKey
	tag string
}

type fakeAttester struct{ name string }

func (f fakeAttester) Attest(_ context.Context, nonce []byte) ([]byte, error) {
	return []byte(f.name + "|" + hex.EncodeToString(nonce)), nil
}

func (w *world) Verify(doc, nonce []byte, pin string) (*attest.Peer, error) {
	name, bound, ok := strings.Cut(string(doc), "|")
	if !ok || bound != hex.EncodeToString(nonce) {
		return nil, errors.New("document is not bound to this nonce")
	}
	r, ok := w.releases[pin][name]
	if !ok {
		return nil, fmt.Errorf("%s isn't a release of %s", name, pin)
	}
	return &attest.Peer{Key: r.key, KeyFingerprint: wire.Fingerprint(r.key), Repo: pin, Tag: r.tag}, nil
}

func (w *world) enroll(pin, name, tag string) *ecdh.PrivateKey {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	if w.releases[pin] == nil {
		w.releases[pin] = map[string]release{}
	}
	w.releases[pin][name] = release{key: key.PublicKey(), tag: tag}
	return key
}

type fixture struct {
	t         *testing.T
	w         *world
	ids       []*age.X25519Identity
	operator  ed25519.PrivateKey
	threshold int
	committed map[string]*node
}

func newFixture(t *testing.T, recipients, threshold int) *fixture {
	t.Helper()
	f := &fixture{t: t, w: &world{releases: map[string]map[string]release{}}, threshold: threshold, committed: map[string]*node{}}
	for range recipients {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		f.ids = append(f.ids, id)
	}
	_, f.operator, _ = ed25519.GenerateKey(rand.Reader)
	return f
}

func (f *fixture) config(commitment string) *vault.Config {
	var recipients []string
	for _, id := range f.ids {
		recipients = append(recipients, id.Recipient().String())
	}
	env := map[string]string{
		"VAULT_REPO":          vaultRepo,
		"EDGE_REPO":           edgeRepo,
		"EDGE_MIN_TAG":        "v1.0.0",
		"KEYSET_COMMITMENT":   commitment,
		"VAULT_PEERS":         "vault-a.example,vault-b.example",
		"RECOVERY_RECIPIENTS": strings.Join(recipients, ","),
		"RECOVERY_THRESHOLD":  fmt.Sprint(f.threshold),
		"OPERATOR_KEY":        hex.EncodeToString(f.operator.Public().(ed25519.PublicKey)),
	}
	c, err := vault.LoadConfig(func(k string) string { return env[k] })
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

type node struct {
	s   *vault.Server
	url string
}

func (f *fixture) vault(name, tag, commitment string) *node {
	f.t.Helper()
	key := f.w.enroll(vaultRepo, name, tag)
	s := vault.NewServer(f.config(commitment), key, fakeAttester{name}, f.w, http.DefaultClient)
	ts := httptest.NewServer(s.Routes())
	f.t.Cleanup(ts.Close)
	return &node{s: s, url: ts.URL}
}

type edge struct {
	key *ecdh.PrivateKey
	a   fakeAttester
}

func (f *fixture) edge(name, tag string) *edge {
	return &edge{key: f.w.enroll(edgeRepo, name, tag), a: fakeAttester{name}}
}

// pull is the edge's whole side: no verification, only the commitment.
func (e *edge) pull(base, commitment string) (*wire.PullResult, error) {
	return wire.Pull(context.Background(), http.DefaultClient, base, e.key, e.a, nil, commitment)
}

func (n *node) status(t *testing.T) map[string]any {
	t.Helper()
	resp, err := http.Get(n.url + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (n *node) post(t *testing.T, path string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(n.url+path, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (n *node) generate(t *testing.T) string {
	t.Helper()
	status, out := n.post(t, "/generate")
	if status != http.StatusOK {
		t.Fatalf("generate answered %d: %v", status, out)
	}
	return out["commitment"].(string)
}

// bootstrap runs steps 1 to 3 of the design: generate in v0.1.0, then a
// committed v0.1.1 pulls the keyset.
func (f *fixture) bootstrap() (commitment string, committed *node) {
	f.t.Helper()
	first := f.vault("vault-a-gen", "v0.1.0", "")
	commitment = first.generate(f.t)
	committed = f.vault("vault-a", "v0.1.1", commitment)
	if err := committed.s.PullFrom(context.Background(), first.url); err != nil {
		f.t.Fatalf("committed release pulling from the generator: %v", err)
	}
	f.committed[commitment] = committed
	return commitment, committed
}

func TestBootstrap(t *testing.T) {
	f := newFixture(t, 2, 1)
	first := f.vault("vault-a-gen", "v0.1.0", "")
	commitment := first.generate(t)
	if status, _ := first.post(t, "/generate"); status != http.StatusConflict {
		t.Fatalf("second generate answered %d", status)
	}
	// With no commitment, an edge would have nothing to check the keys against.
	if _, err := f.edge("edge", "v1.0.0").pull(first.url, commitment); err == nil || !strings.Contains(err.Error(), "refused at commitment") {
		t.Fatalf("generator release served an edge: %v", err)
	}

	committed := f.vault("vault-a", "v0.1.1", commitment)
	if status, _ := committed.post(t, "/generate"); status != http.StatusConflict {
		t.Fatalf("committed release generated, answered %d", status)
	}
	if err := committed.s.PullFrom(context.Background(), first.url); err != nil {
		t.Fatal(err)
	}
	if got := committed.status(t)["keyset_commitment"]; got != commitment {
		t.Fatalf("pulled keyset %v, want %s", got, commitment)
	}
	// The generator is now below every committed release, so it never gets keys back.
	regen := f.vault("vault-a-gen-2", "v0.1.0", "")
	if err := regen.s.PullFrom(context.Background(), committed.url); err == nil || !strings.Contains(err.Error(), "minimum tag") {
		t.Fatalf("generator release pulled from a committed one: %v", err)
	}
}

func TestEdgeGetsKeysetAndCredentials(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, v := f.bootstrap()
	f.importS3(t, v, wire.S3Credentials{AccessKeyID: "AKIA", SecretAccessKey: "secret"})

	got, err := f.edge("edge", "v1.2.0").pull(v.url, commitment)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Keyset.Matches(commitment) || got.S3 == nil || got.S3.SecretAccessKey != "secret" {
		t.Fatalf("edge got %+v", got)
	}
}

func TestEdgeBelowMinimumGetsNothing(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, v := f.bootstrap()
	_, err := f.edge("old-edge", "v0.9.9").pull(v.url, commitment)
	if err == nil || !strings.Contains(err.Error(), "refused at minimum tag") {
		t.Fatalf("old edge: %v", err)
	}
}

func TestVaultBelowOwnTagGetsNothing(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, v := f.bootstrap()
	upgraded := f.vault("vault-a-next", "v0.2.0", commitment)
	if err := upgraded.s.PullFrom(context.Background(), v.url); err != nil {
		t.Fatalf("upgrade pulling from an older vault: %v", err)
	}
	stale := f.vault("vault-b", "v0.1.1", commitment)
	if err := stale.s.PullFrom(context.Background(), upgraded.url); err == nil || !strings.Contains(err.Error(), "minimum tag") {
		t.Fatalf("v0.1.1 pulled from v0.2.0: %v", err)
	}
}

func TestStrangerGetsNothing(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, v := f.bootstrap()
	stranger := &edge{key: f.w.enroll("someone/else", "x", "v9.0.0"), a: fakeAttester{"x"}}
	_, err := stranger.pull(v.url, commitment)
	if err == nil || !strings.Contains(err.Error(), "refused at verify") {
		t.Fatalf("stranger: %v", err)
	}
}

func TestEdgeRefusesAnotherKeyset(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, _ := f.bootstrap()
	other, err := wire.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// A verified vault whose release commits to the right keyset, but which holds
	// another: only the edge's own check can catch this.
	rogue := f.vault("rogue", "v0.1.1", commitment)
	rogue.s.ForceKeyset(other)
	if _, err := f.edge("edge", "v1.0.0").pull(rogue.url, commitment); err == nil || !strings.Contains(err.Error(), "doesn't match the commitment") {
		t.Fatalf("edge accepted another keyset: %v", err)
	}
}

func TestVaultRefusesUnverifiedHolder(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, _ := f.bootstrap()
	// An edge release holds the keys but isn't a vault, so a vault won't take them
	// from it, even with the right keyset.
	impostor := f.w.enroll(edgeRepo, "impostor", "v1.0.0")
	holder := holderServer(t, f.w, impostor, fakeAttester{"impostor"}, keysetFor(t, f, commitment))
	fresh := f.vault("vault-b", "v0.1.1", commitment)
	if err := fresh.s.PullFrom(context.Background(), holder); err == nil || !strings.Contains(err.Error(), "verifying holder") {
		t.Fatalf("vault took keys from a non-vault: %v", err)
	}
}

func TestVaultRefusesHolderKeyNotInDocument(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, _ := f.bootstrap()
	f.w.enroll(vaultRepo, "real-vault", "v0.1.1")
	// The document is a real vault's, but the box comes from another key.
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	holder := holderServer(t, f.w, other, fakeAttester{"real-vault"}, keysetFor(t, f, commitment))
	fresh := f.vault("vault-b", "v0.1.1", commitment)
	if err := fresh.s.PullFrom(context.Background(), holder); err == nil || !strings.Contains(err.Error(), "isn't the one its document endorses") {
		t.Fatalf("vault accepted a key its holder's document doesn't endorse: %v", err)
	}
}

func TestNoncesAreSingleUseAndBoundToTheirExchange(t *testing.T) {
	f := newFixture(t, 2, 1)
	_, v := f.bootstrap()
	e := f.edge("edge", "v1.0.0")

	_, begun := v.post(t, "/transfer/begin")
	nonce := begun["nonce"].(string)
	raw, _ := hex.DecodeString(nonce)
	doc, _ := e.a.Attest(context.Background(), raw)
	answer := hex.EncodeToString(bytes.Repeat([]byte{7}, wire.NonceSize))
	req := wire.FinishRequest{Nonce: nonce, AnswerNonce: answer, Document: doc}
	var out wire.FinishResponse
	if err := wire.PostJSON(context.Background(), http.DefaultClient, v.url+"/transfer/finish", req, &out); err != nil {
		t.Fatal(err)
	}
	if err := wire.PostJSON(context.Background(), http.DefaultClient, v.url+"/transfer/finish", req, &out); err == nil || !strings.Contains(err.Error(), "refused at nonce") {
		t.Fatalf("replayed nonce: %v", err)
	}

	// A nonce issued for an operator exchange can't finish a transfer.
	var op vault.OperatorBeginResponse
	if err := wire.PostJSON(context.Background(), http.DefaultClient, v.url+"/operator/begin", vault.OperatorBeginRequest{AnswerNonce: answer}, &op); err != nil {
		t.Fatal(err)
	}
	raw, _ = hex.DecodeString(op.Nonce)
	doc, _ = e.a.Attest(context.Background(), raw)
	req = wire.FinishRequest{Nonce: op.Nonce, AnswerNonce: answer, Document: doc}
	if err := wire.PostJSON(context.Background(), http.DefaultClient, v.url+"/transfer/finish", req, &out); err == nil || !strings.Contains(err.Error(), "issued for operator") {
		t.Fatalf("operator nonce finished a transfer: %v", err)
	}
}

func TestVaultFailsClosedWithoutItsOwnTag(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, _ := f.bootstrap()
	untagged := f.vault("untagged", "latest", commitment)
	untagged.s.ForceKeyset(keysetFor(t, f, commitment))
	peer := f.vault("vault-b", "v0.1.1", commitment)
	if err := peer.s.PullFrom(context.Background(), untagged.url); err == nil || !strings.Contains(err.Error(), "own release tag") {
		t.Fatalf("holder with no tag served a vault: %v", err)
	}
}

func TestRestoreFromShares(t *testing.T) {
	f := newFixture(t, 3, 2)
	commitment, v := f.bootstrap()
	bundle, err := f.operatorClient(v, "vault-a").Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Commitment != commitment || bundle.Threshold != 2 || len(bundle.Shares) != 3 {
		t.Fatalf("bundle %+v", bundle)
	}

	fresh := f.vault("vault-fresh", "v0.1.1", commitment)
	c := f.operatorClient(fresh, "vault-fresh")
	first := f.decrypt(t, bundle, 0)
	if restored, err := c.SubmitShare(context.Background(), first); err != nil || restored {
		t.Fatalf("one share of two: restored=%v, %v", restored, err)
	}
	junk := append([]byte{3}, bytes.Repeat([]byte{0xaa}, len(first)-1)...)
	if restored, err := c.SubmitShare(context.Background(), junk); err != nil || restored {
		t.Fatalf("junk share: restored=%v, %v", restored, err)
	}
	if restored, err := c.SubmitShare(context.Background(), f.decrypt(t, bundle, 2)); err != nil || !restored {
		t.Fatalf("second real share: restored=%v, %v", restored, err)
	}
	if got := fresh.status(t)["keyset_commitment"]; got != commitment {
		t.Fatalf("restored %v, want %s", got, commitment)
	}
}

func TestSharesOfAnotherKeysetDontRestore(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, _ := f.bootstrap()
	otherCommitment, other := newFixture(t, 0, 0).withIDs(f).bootstrap()
	if otherCommitment == commitment {
		t.Fatal("two bootstraps made the same keyset")
	}
	bundle, err := f.operatorClient(other, "vault-a").Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fresh := f.vault("vault-fresh", "v0.1.1", commitment)
	if restored, err := f.operatorClient(fresh, "vault-fresh").SubmitShare(context.Background(), f.decrypt(t, bundle, 0)); err != nil || restored {
		t.Fatalf("another keyset's share: restored=%v, %v", restored, err)
	}
}

func TestImportNeedsTheOperatorKey(t *testing.T) {
	f := newFixture(t, 2, 1)
	_, v := f.bootstrap()
	c := f.operatorClient(v, "vault-a")
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	err := c.ImportS3(context.Background(), wire.S3Credentials{AccessKeyID: "A", SecretAccessKey: "B"}, wrong)
	if err == nil || !strings.Contains(err.Error(), "refused at signature") {
		t.Fatalf("import with another key: %v", err)
	}
	if v.status(t)["has_s3"] != false {
		t.Fatal("unsigned import stored credentials")
	}
	f.importS3(t, v, wire.S3Credentials{AccessKeyID: "A", SecretAccessKey: "B"})
	if v.status(t)["has_s3"] != true {
		t.Fatal("signed import didn't store credentials")
	}
}

func TestOperatorRefusesUnverifiedVault(t *testing.T) {
	f := newFixture(t, 2, 1)
	_, v := f.bootstrap()
	c := f.operatorClient(v, "vault-a")
	c.Verify = func(doc, nonce []byte) (*ecdh.PublicKey, error) { return nil, errors.New("wrong release") }
	if _, err := c.SubmitShare(context.Background(), []byte{1, 2}); err == nil || !strings.Contains(err.Error(), "verifying vault") {
		t.Fatalf("submitted to an unverified vault: %v", err)
	}
}

func TestBundleNeedsAKeyset(t *testing.T) {
	f := newFixture(t, 2, 1)
	empty := f.vault("empty", "v0.1.1", strings.Repeat("a", 64))
	if _, err := f.operatorClient(empty, "empty").Bundle(context.Background()); err == nil {
		t.Fatal("empty vault produced a bundle")
	}
}

func TestLoadConfigRejectsMistakes(t *testing.T) {
	f := newFixture(t, 2, 1)
	base := map[string]string{
		"VAULT_REPO": vaultRepo, "EDGE_REPO": edgeRepo, "EDGE_MIN_TAG": "v1.0.0",
		"VAULT_PEERS": "vault-a.example", "RECOVERY_RECIPIENTS": f.ids[0].Recipient().String(),
		"RECOVERY_THRESHOLD": "1", "OPERATOR_KEY": hex.EncodeToString(f.operator.Public().(ed25519.PublicKey)),
	}
	if _, err := vault.LoadConfig(func(k string) string { return base[k] }); err != nil {
		t.Fatal(err)
	}
	for key, bad := range map[string]string{
		"VAULT_REPO":          vaultRepo + "@v1.0.0",
		"EDGE_REPO":           vaultRepo,
		"EDGE_MIN_TAG":        "1.0.0",
		"KEYSET_COMMITMENT":   "ABC",
		"VAULT_PEERS":         "https://vault-a.example",
		"RECOVERY_RECIPIENTS": "age1nope",
		"RECOVERY_THRESHOLD":  "2",
		"OPERATOR_KEY":        "00",
	} {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		env[key] = bad
		if _, err := vault.LoadConfig(func(k string) string { return env[k] }); err == nil {
			t.Errorf("%s=%q loaded", key, bad)
		}
	}
}

// withIDs shares recipients and the operator key, so two fixtures differ only in
// their keysets.
func (f *fixture) withIDs(from *fixture) *fixture {
	f.t, f.ids, f.operator, f.threshold = from.t, from.ids, from.operator, from.threshold
	f.w = from.w
	return f
}

func (f *fixture) operatorClient(n *node, name string) *opclient.Client {
	return &opclient.Client{HTTP: http.DefaultClient, Base: n.url, Verify: func(doc, nonce []byte) (*ecdh.PublicKey, error) {
		p, err := f.w.Verify(doc, nonce, vaultRepo)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(string(doc), name+"|") {
			return nil, errors.New("another vault")
		}
		return p.Key, nil
	}}
}

func (f *fixture) importS3(t *testing.T, n *node, creds wire.S3Credentials) {
	t.Helper()
	if err := f.operatorClient(n, f.nameOf(t, n)).ImportS3(context.Background(), creds, f.operator); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) nameOf(t *testing.T, n *node) string {
	t.Helper()
	fp := n.status(t)["transfer_key_fp"]
	for name, r := range f.w.releases[vaultRepo] {
		if wire.Fingerprint(r.key) == fp {
			return name
		}
	}
	t.Fatal("node isn't an enrolled vault")
	return ""
}

func (f *fixture) decrypt(t *testing.T, b interface {
	Decrypt([]age.Identity) ([][]byte, error)
}, i int) []byte {
	t.Helper()
	shares, err := b.Decrypt([]age.Identity{f.ids[i]})
	if err != nil {
		t.Fatal(err)
	}
	return shares[0]
}

// keysetFor fetches the committed keyset through an edge, the only way out of a vault.
func keysetFor(t *testing.T, f *fixture, commitment string) *wire.Keyset {
	t.Helper()
	holder, ok := f.committed[commitment]
	if !ok {
		t.Fatal("no committed vault for this commitment")
	}
	got, err := f.edge(fmt.Sprintf("keyset-reader-%d", len(f.w.releases[edgeRepo])), "v1.0.0").pull(holder.url, commitment)
	if err != nil {
		t.Fatal(err)
	}
	return got.Keyset
}

// holderServer answers a transfer like a vault, sealing from key, with documents
// from a. It does no checks of its own.
func holderServer(t *testing.T, w *world, key *ecdh.PrivateKey, a fakeAttester, k *wire.Keyset) string {
	t.Helper()
	var issued []byte
	mux := http.NewServeMux()
	mux.HandleFunc("POST /transfer/begin", func(rw http.ResponseWriter, _ *http.Request) {
		issued, _ = wire.RandomNonce()
		json.NewEncoder(rw).Encode(wire.BeginResponse{Nonce: hex.EncodeToString(issued)})
	})
	mux.HandleFunc("POST /transfer/finish", func(rw http.ResponseWriter, r *http.Request) {
		var req wire.FinishRequest
		json.NewDecoder(r.Body).Decode(&req)
		answer, _ := wire.DecodeNonce(req.AnswerNonce)
		requester, err := w.Verify(req.Document, issued, vaultRepo)
		if err != nil {
			t.Errorf("holder couldn't read the requester: %v", err)
			return
		}
		payload, _ := json.Marshal(wire.Payload{Keyset: k.MarshalBinary()})
		sealed, err := wire.Seal(wire.PurposeKeyset, key, requester.Key, wire.Nonces{Issued: issued, Answer: answer}, payload)
		if err != nil {
			t.Error(err)
		}
		doc, _ := a.Attest(r.Context(), answer)
		json.NewEncoder(rw).Encode(wire.FinishResponse{Document: doc, HolderKey: key.PublicKey().Bytes(), Sealed: sealed})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts.URL
}

func TestUntaggedEdgeGetsNothing(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, v := f.bootstrap()
	if _, err := f.edge("edge", "").pull(v.url, commitment); err == nil || !strings.Contains(err.Error(), "refused at minimum tag") {
		t.Fatalf("untagged edge: %v", err)
	}
}

func TestOperatorRefusesKeyNotInDocument(t *testing.T) {
	f := newFixture(t, 2, 1)
	f.w.enroll(vaultRepo, "real-vault", "v0.1.1")
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	// A real vault's document, but the key offered for sealing is someone else's.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /operator/begin", func(w http.ResponseWriter, r *http.Request) {
		var req vault.OperatorBeginRequest
		json.NewDecoder(r.Body).Decode(&req)
		answer, _ := wire.DecodeNonce(req.AnswerNonce)
		doc, _ := fakeAttester{"real-vault"}.Attest(r.Context(), answer)
		nonce, _ := wire.RandomNonce()
		json.NewEncoder(w).Encode(vault.OperatorBeginResponse{Nonce: hex.EncodeToString(nonce), Document: doc, VaultKey: other.PublicKey().Bytes()})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	c := f.operatorClient(&node{url: ts.URL}, "real-vault")
	if _, err := c.SubmitShare(context.Background(), []byte{1, 2}); err == nil || !strings.Contains(err.Error(), "isn't the one its document endorses") {
		t.Fatalf("sealed to a key the document doesn't endorse: %v", err)
	}
}
