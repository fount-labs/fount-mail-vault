package vault_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-vault/internal/vault"
	"github.com/fount-labs/fount-mail-vault/wire"
)

const (
	tagSendGen = "v0.2.0" // release N: KEYSET_COMMITMENT, no SEND_KEYSET_COMMITMENT
	tagSend    = "v0.3.0" // release N+1: both
)

func (n *node) generateSend(t *testing.T) string {
	t.Helper()
	status, out := n.post(t, "/generate-send")
	if status != http.StatusOK {
		t.Fatalf("generate-send answered %d: %v", status, out)
	}
	return out["send_commitment"].(string)
}

// pullBoth is a send-aware edge's side.
func (e *edge) pullBoth(base string, want wire.Commitments) (*wire.PullResult, error) {
	return wire.PullKeysets(context.Background(), http.DefaultClient, base, e.key, e.a, nil, want)
}

// sendBootstrap runs the send lifecycle: release N pulls the committed keyset and
// generates the send keyset, then release N+1 pins it and pulls both.
func (f *fixture) sendBootstrap() (commitment, send string, gen, pinned *node) {
	f.t.Helper()
	commitment, v := f.bootstrap()
	gen = f.vault("vault-a-send-gen", tagSendGen, commitment)
	if err := gen.s.PullFrom(context.Background(), v.url); err != nil {
		f.t.Fatal(err)
	}
	send = gen.generateSend(f.t)
	pinned = f.vaultWith("vault-a-send", tagSend, commitment, send, http.DefaultClient)
	if err := pinned.s.PullFrom(context.Background(), gen.url); err != nil {
		f.t.Fatalf("pinned release pulling from the send generator: %v", err)
	}
	return commitment, send, gen, pinned
}

func TestSendKeysetLifecycle(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, v := f.bootstrap()

	// Release N: generate-send needs the keyset first.
	empty := f.vault("vault-empty", tagSendGen, commitment)
	if status, out := empty.post(t, "/generate-send"); status != http.StatusConflict || !strings.Contains(out["error"].(string), "holds no keyset") {
		t.Fatalf("generate-send with no keyset answered %d: %v", status, out)
	}
	gen := f.vault("vault-a-send-gen", tagSendGen, commitment)
	if err := gen.s.PullFrom(context.Background(), v.url); err != nil {
		t.Fatal(err)
	}
	if err := gen.s.PullFrom(context.Background(), v.url); err == nil {
		t.Fatal("a release with no send commitment pulled again after it held the keyset")
	}
	send := gen.generateSend(t)
	if status, _ := gen.post(t, "/generate-send"); status != http.StatusConflict {
		t.Fatalf("second generate-send answered %d", status)
	}
	st := gen.status(t)
	if st["has_send_keyset"] != true || st["send_keyset_commitment"] != send || st["send_source"] != "generated" || st["config_send_commitment"] != "" {
		t.Fatalf("status after generate-send: %v", st)
	}
	if st["keyset_commitment"] != commitment {
		t.Fatal("generate-send changed the keyset")
	}

	// Release N serves the send keyset to vaults, but not to edges, which have
	// nothing to check it against.
	e := f.edge("edge", "v1.0.0")
	got, err := e.pullBoth(gen.url, wire.Commitments{Keyset: commitment, Send: send})
	if err != nil || got.SendKeyset != nil {
		t.Fatalf("release N served an edge the send keyset: %v, %v", got, err)
	}
	peer := f.vault("vault-b-send-gen", tagSendGen, commitment)
	if err := peer.s.PullFrom(context.Background(), gen.url); err != nil {
		t.Fatal(err)
	}
	if peer.status(t)["send_keyset_commitment"] != send {
		t.Fatal("a release-N vault restarting from its peer didn't get the send keyset")
	}

	// Release N+1 pins it, can't generate, and pulls both from release N.
	pinned := f.vaultWith("vault-a-send", tagSend, commitment, send, http.DefaultClient)
	if status, out := pinned.post(t, "/generate-send"); status != http.StatusConflict || !strings.Contains(out["error"].(string), "send commitment") {
		t.Fatalf("pinned release generated a send keyset, answered %d: %v", status, out)
	}
	if err := pinned.s.PullFrom(context.Background(), gen.url); err != nil {
		t.Fatal(err)
	}
	if st := pinned.status(t); st["send_keyset_commitment"] != send || st["keyset_commitment"] != commitment || st["config_send_commitment"] != send {
		t.Fatalf("pinned release status %v", st)
	}

	// A send-aware edge gets both. An edge that predates the send keyset, which
	// calls wire.Pull, still gets the keyset and nothing else.
	got, err = e.pullBoth(pinned.url, wire.Commitments{Keyset: commitment, Send: send})
	if err != nil || got.SendKeyset == nil || !got.SendKeyset.Matches(send) || !got.Keyset.Matches(commitment) {
		t.Fatalf("send-aware edge: %+v, %v", got, err)
	}
	checkSendPublic(t, pinned.status(t)["send_public"], got.SendKeyset)
	old, err := f.edge("edge-v0.2.1", "v1.0.0").pull(pinned.url, commitment)
	if err != nil || old.SendKeyset != nil || !old.Keyset.Matches(commitment) {
		t.Fatalf("an edge without the send keyset: %+v, %v", old, err)
	}
	// A send-aware edge with no send commitment yet ignores it.
	got, err = e.pullBoth(pinned.url, wire.Commitments{Keyset: commitment})
	if err != nil || got.SendKeyset != nil {
		t.Fatalf("edge with no send commitment: %+v, %v", got, err)
	}
}

func TestGenerateSendNeedsAKeysetCommitment(t *testing.T) {
	f := newFixture(t, 2, 1)
	first := f.vault("vault-a-gen", "v0.1.0", "")
	first.generate(t)
	if status, out := first.post(t, "/generate-send"); status != http.StatusConflict || !strings.Contains(out["error"].(string), "no keyset commitment") {
		t.Fatalf("generator release generated a send keyset, answered %d: %v", status, out)
	}
	if first.status(t)["has_send_keyset"] != false {
		t.Fatal("generator release holds a send keyset")
	}
}

func TestPinnedVaultAndEdgeRefuseAnotherSendKeyset(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, send, _, pinned := f.sendBootstrap()
	other, err := wire.GenerateSend()
	if err != nil {
		t.Fatal(err)
	}
	// A verified vault whose release commits to the right send keyset, but which
	// holds another.
	rogue := f.vaultWith("rogue", tagSend, commitment, send, http.DefaultClient)
	if err := rogue.s.PullFrom(context.Background(), pinned.url); err != nil {
		t.Fatal(err)
	}
	rogue.s.ForceSendKeyset(other)
	fresh := f.vaultWith("vault-b-send", tagSend, commitment, send, http.DefaultClient)
	if err := fresh.s.PullFrom(context.Background(), rogue.url); err == nil || !strings.Contains(err.Error(), "doesn't match the send commitment") {
		t.Fatalf("vault accepted another send keyset: %v", err)
	}
	if fresh.status(t)["has_keyset"] != false {
		t.Fatal("a pull with the wrong send keyset installed the keyset")
	}
	want := wire.Commitments{Keyset: commitment, Send: send}
	if _, err := f.edge("edge", "v1.0.0").pullBoth(rogue.url, want); err == nil || !strings.Contains(err.Error(), "doesn't match the send commitment") {
		t.Fatalf("edge accepted another send keyset: %v", err)
	}
	// An edge that predates the send keyset never reads it, so the rogue send
	// keyset can't stop it.
	if _, err := f.edge("edge-v0.2.1", "v1.0.0").pull(rogue.url, commitment); err != nil {
		t.Fatal(err)
	}
}

// routed sends https://<name> to the test server for that name, the way the
// restore loop dials VAULT_PEERS.
func routed(t *testing.T, routes map[string]*httptest.Server) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	for _, ts := range routes {
		pool.AddCert(ts.Certificate())
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, _ := strings.Cut(addr, ":")
			ts, ok := routes[host]
			if !ok {
				return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
			}
			return (&net.Dialer{}).DialContext(ctx, network, ts.Listener.Addr().String())
		},
	}}
}

// tlsVault serves s over TLS, as a peer the restore loop can reach by name.
func tlsVault(t *testing.T, s *vault.Server) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(s.Routes())
	t.Cleanup(ts.Close)
	return ts
}

func TestRestartGetsTheSendKeysetFromWhicheverPeerHasIt(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, send, _, pinned := f.sendBootstrap()

	// vault-a.example holds only the keyset, as after a recovery from shares.
	// vault-b.example holds both.
	mailOnly := f.vaultWith("vault-a-shares", tagSend, commitment, send, http.DefaultClient)
	mailOnly.s.ForceKeyset(keysetFor(t, f, commitment))
	routes := map[string]*httptest.Server{"vault-a.example": tlsVault(t, mailOnly.s), "vault-b.example": tlsVault(t, pinned.s)}

	restarted := f.vaultWith("vault-b-restarted", tagSend, commitment, send, routed(t, routes))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	restarted.s.RestoreFromPeers(ctx)
	st := restarted.status(t)
	if st["keyset_commitment"] != commitment || st["send_keyset_commitment"] != send {
		t.Fatalf("restarted vault: %v", st)
	}
	if !strings.Contains(st["send_source"].(string), "vault-b.example") {
		t.Fatalf("send keyset came from %v", st["send_source"])
	}

	// The vault that had only the keyset gets the send keyset from its peer on its
	// next pull, without giving up the keyset it holds.
	if err := mailOnly.s.PullFrom(context.Background(), pinned.url); err != nil {
		t.Fatal(err)
	}
	if mailOnly.status(t)["send_keyset_commitment"] != send {
		t.Fatal("a vault holding the keyset didn't take the send keyset from its peer")
	}
	if err := mailOnly.s.PullFrom(context.Background(), pinned.url); err == nil {
		t.Fatal("a complete vault pulled again")
	}
}

func TestRestartWithNoSendKeysetAnywhereKeepsTheKeyset(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, send, _, _ := f.sendBootstrap()
	mailOnly := f.vaultWith("vault-a-shares", tagSend, commitment, send, http.DefaultClient)
	mailOnly.s.ForceKeyset(keysetFor(t, f, commitment))
	routes := map[string]*httptest.Server{"vault-a.example": tlsVault(t, mailOnly.s)}

	restarted := f.vaultWith("vault-b-restarted", tagSend, commitment, send, routed(t, routes))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	restarted.s.RestoreFromPeers(ctx)
	st := restarted.status(t)
	if st["keyset_commitment"] != commitment || st["has_send_keyset"] != false {
		t.Fatalf("restarted vault: %v", st)
	}
	// It still serves the keyset, so a restarting edge can receive mail.
	got, err := f.edge("edge", "v1.0.0").pullBoth(restarted.url, wire.Commitments{Keyset: commitment, Send: send})
	if err != nil || got.SendKeyset != nil {
		t.Fatalf("edge from a vault with no send keyset: %+v, %v", got, err)
	}
}

func TestRecoveryLeavesTheSendKeysetToPeers(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, send, _, pinned := f.sendBootstrap()
	bundle, err := f.operatorClient(pinned, "vault-a-send").Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Commitment != commitment {
		t.Fatalf("bundle is for %s, want the keyset %s", bundle.Commitment, commitment)
	}
	fresh := f.vaultWith("vault-fresh", tagSend, commitment, send, http.DefaultClient)
	if restored, err := f.operatorClient(fresh, "vault-fresh").SubmitShare(context.Background(), f.decrypt(t, bundle, 0)); err != nil || !restored {
		t.Fatalf("restore: %v, %v", restored, err)
	}
	if st := fresh.status(t); st["has_keyset"] != true || st["has_send_keyset"] != false {
		t.Fatalf("restored vault: %v", st)
	}
	if err := fresh.s.PullFrom(context.Background(), pinned.url); err != nil {
		t.Fatal(err)
	}
	if fresh.status(t)["send_keyset_commitment"] != send {
		t.Fatal("restored vault didn't take the send keyset from a peer")
	}
}

func TestLoadConfigRejectsSendCommitmentMistakes(t *testing.T) {
	f := newFixture(t, 2, 1)
	good := strings.Repeat("a", 64)
	base := map[string]string{
		"VAULT_REPO": vaultRepo, "EDGE_REPO": edgeRepo, "EDGE_MIN_TAG": "v1.0.0",
		"KEYSET_COMMITMENT": good, "SEND_KEYSET_COMMITMENT": strings.Repeat("b", 64),
		"VAULT_PEERS": "vault-a.example", "RECOVERY_RECIPIENTS": f.ids[0].Recipient().String(),
		"RECOVERY_THRESHOLD": "1", "OPERATOR_KEY": hex.EncodeToString(f.operator.Public().(ed25519.PublicKey)),
	}
	if _, err := vault.LoadConfig(func(k string) string { return base[k] }); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]map[string]string{
		"uppercase":         {"SEND_KEYSET_COMMITMENT": strings.Repeat("B", 64)},
		"short":             {"SEND_KEYSET_COMMITMENT": "abc"},
		"no keyset":         {"KEYSET_COMMITMENT": ""},
		"same as keyset":    {"SEND_KEYSET_COMMITMENT": good},
		"trailing space":    {"SEND_KEYSET_COMMITMENT": strings.Repeat("b", 64) + " "},
		"keyset is invalid": {"KEYSET_COMMITMENT": "ABC"},
	} {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		for k, v := range edit {
			env[k] = v
		}
		if _, err := vault.LoadConfig(func(k string) string { return env[k] }); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// checkSendPublic compares /status's public halves with the send keyset an edge
// pulled, computed the way the edge's dkim.TXTRecord and gatewaytls.PinOf do.
func checkSendPublic(t *testing.T, got any, k *wire.SendKeyset) {
	t.Helper()
	pub, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("send_public is %T", got)
	}
	rsaKey, _ := k.DKIMRSA()
	rsaSPKI, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	dkimEd, _ := k.DKIMEd25519()
	relay, _ := k.RelayClient()
	relaySPKI, _ := x509.MarshalPKIXPublicKey(relay.Public())
	pin := sha256.Sum256(relaySPKI)
	want := map[string]string{
		"dkim_rsa_txt":     "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(rsaSPKI),
		"dkim_ed25519_txt": "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(dkimEd.Public().(ed25519.PublicKey)),
		"relay_client_pin": hex.EncodeToString(pin[:]),
	}
	for field, w := range want {
		if pub[field] != w {
			t.Errorf("send_public.%s = %v, want %s", field, pub[field], w)
		}
	}
}

// splitEdge is a split edge's two containers: core holds `transfer`, send holds
// `send-transfer`, and both attest with the enclave's one document.
type splitEdge struct {
	core     *edge
	sendKey  *ecdh.PrivateKey
	attester fakeAttester
}

func (f *fixture) splitEdge(name, tag string) *splitEdge {
	core := f.edge(name, tag)
	sendKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	r := f.w.releases[edgeRepo][name]
	r.sendKey = sendKey.PublicKey()
	f.w.releases[edgeRepo][name] = r
	return &splitEdge{core: core, sendKey: sendKey, attester: core.a}
}

func (e *splitEdge) pullSend(base, send string) (*wire.SendPullResult, error) {
	return wire.PullSendKeyset(context.Background(), http.DefaultClient, base, e.sendKey, e.attester, nil, send)
}

func TestSplitEdgeGetsTheSendKeysetInItsOwnBox(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, send, gen, pinned := f.sendBootstrap()
	e := f.splitEdge("edge-split", "v1.0.0")
	want := wire.Commitments{Keyset: commitment, Send: send}

	// Core opens the keyset's box, which leaves the send keyset out.
	core, err := e.core.pullBoth(pinned.url, want)
	if err != nil || !core.Keyset.Matches(commitment) || core.SendKeyset != nil {
		t.Fatalf("core: %+v, %v", core, err)
	}
	// The send container opens only the send keyset's box.
	got, err := e.pullSend(pinned.url, send)
	if err != nil || got.SendKeyset == nil || !got.SendKeyset.Matches(send) {
		t.Fatalf("send container: %+v, %v", got, err)
	}
	checkSendPublic(t, pinned.status(t)["send_public"], got.SendKeyset)

	// Neither key opens the other's box.
	raw := finishFor(t, pinned.url, e.attester)
	if len(raw.SendSealed) == 0 {
		t.Fatal("no send box for a document that endorses send-transfer")
	}
	holder, _ := wire.ParseRawKey(raw.HolderKey)
	if _, err := wire.Open(wire.PurposeSendKeyset, e.core.key, holder, raw.nonces, raw.SendSealed); err == nil {
		t.Fatal("the transfer key opened the send keyset's box")
	}
	if _, err := wire.Open(wire.PurposeKeyset, e.sendKey, holder, raw.nonces, raw.Sealed); err == nil {
		t.Fatal("the send-transfer key opened the keyset's box")
	}
	if _, err := wire.Open(wire.PurposeKeyset, e.sendKey, holder, raw.nonces, raw.SendSealed); err == nil {
		t.Fatal("the send keyset's box opened under the keyset's purpose")
	}

	// A wrong send commitment fails the send container's pull.
	if _, err := e.pullSend(pinned.url, strings.Repeat("c", 64)); err == nil || !strings.Contains(err.Error(), "doesn't match the send commitment") {
		t.Fatalf("send container took another send keyset: %v", err)
	}
	// A release with no send commitment gives an edge no send box.
	if got, err := e.pullSend(gen.url, send); err != nil || got.SendKeyset != nil {
		t.Fatalf("release N gave a split edge the send keyset: %+v, %v", got, err)
	}
	// Edges without send-transfer keep the single box.
	old, err := f.edge("edge-v0.3.0", "v1.0.0").pullBoth(pinned.url, want)
	if err != nil || old.SendKeyset == nil || !old.SendKeyset.Matches(send) {
		t.Fatalf("an edge with no send-transfer key: %+v, %v", old, err)
	}
	// And a vault restarting from its peer still gets everything in one box.
	peer := f.vaultWith("vault-b-send", tagSend, commitment, send, http.DefaultClient)
	if err := peer.s.PullFrom(context.Background(), pinned.url); err != nil || peer.status(t)["send_keyset_commitment"] != send {
		t.Fatalf("vault peer: %v, %v", err, peer.status(t))
	}
}

func TestSplitEdgeFromAVaultWithNoSendKeyset(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, send, _, _ := f.sendBootstrap()
	mailOnly := f.vaultWith("vault-a-shares", tagSend, commitment, send, http.DefaultClient)
	mailOnly.s.ForceKeyset(keysetFor(t, f, commitment))
	e := f.splitEdge("edge-split", "v1.0.0")
	if got, err := e.pullSend(mailOnly.url, send); err != nil || got.SendKeyset != nil {
		t.Fatalf("send container from a vault with no send keyset: %+v, %v", got, err)
	}
	if _, err := e.pullSend(mailOnly.url, ""); err == nil {
		t.Fatal("a send pull with no commitment and no holder check ran")
	}
}

type rawFinish struct {
	wire.FinishResponse
	nonces wire.Nonces
}

// finishFor runs begin and finish by hand, to look at both boxes.
func finishFor(t *testing.T, base string, a fakeAttester) rawFinish {
	t.Helper()
	ctx := context.Background()
	var begun wire.BeginResponse
	if err := wire.PostJSON(ctx, http.DefaultClient, base+"/transfer/begin", nil, &begun); err != nil {
		t.Fatal(err)
	}
	issued, _ := wire.DecodeNonce(begun.Nonce)
	answer, _ := wire.RandomNonce()
	doc, _ := a.Attest(ctx, issued)
	var out rawFinish
	req := wire.FinishRequest{Nonce: begun.Nonce, AnswerNonce: hex.EncodeToString(answer), Document: doc}
	if err := wire.PostJSON(ctx, http.DefaultClient, base+"/transfer/finish", req, &out.FinishResponse); err != nil {
		t.Fatal(err)
	}
	out.nonces = wire.Nonces{Issued: issued, Answer: answer}
	return out
}
