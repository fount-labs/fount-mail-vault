package vault_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-vault/internal/vault"
	"github.com/fount-labs/fount-mail-vault/wire"
)

// To a Cloud vault the coordinator is an edge: its config repo is EDGE_REPO.
const coordRepo = edgeRepo

// router sends https://<name> to whichever test server holds that name now,
// so a test can take a vault down, restart it, or promote a candidate. Any
// other address is dialled as it is.
type router struct {
	mu     sync.Mutex
	routes map[string]*httptest.Server
	pool   *x509.CertPool
}

func newRouter(t *testing.T) *router {
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(ts.Close)
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate()) // every httptest TLS server has this one
	return &router{routes: map[string]*httptest.Server{}, pool: pool}
}

func (r *router) set(host string, ts *httptest.Server) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes[host] = ts
}

func (r *router) down(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.routes, host)
}

func (r *router) client() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		// A pooled connection would outlive a route taken down or moved.
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{RootCAs: r.pool, ServerName: "example.com"},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, _ := strings.Cut(addr, ":")
			r.mu.Lock()
			ts, named := r.routes[host]
			r.mu.Unlock()
			if strings.HasSuffix(host, ".example") {
				if !named {
					return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
				}
				addr = ts.Listener.Addr().String()
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
}

const (
	hostA = "vault-a.example"
	hostB = "vault-b.example"
)

type cloud struct {
	t          *testing.T
	f          *fixture
	r          *router
	commitment string
	authority  string
	nodes      map[string]*cloudNode
}

type cloudNode struct {
	s  *vault.Server
	ts *httptest.Server
}

func (c *cloud) config(authority string, floor, count uint64) *vault.Config {
	c.t.Helper()
	env := map[string]string{
		"VAULT_REPO":               vaultRepo,
		"EDGE_REPO":                coordRepo,
		"EDGE_MIN_TAG":             "v1.0.0",
		"KEYSET_COMMITMENT":        c.commitment,
		"VAULT_PEERS":              hostA + "," + hostB,
		"RECOVERY_RECIPIENTS":      c.f.ids[0].Recipient().String(),
		"RECOVERY_THRESHOLD":       "1",
		"OPERATOR_KEY":             hex.EncodeToString(c.f.operator.Public().(ed25519.PublicKey)),
		"COORDINATOR_MODE":         "1",
		"GENERATION_AUTHORITY_KEY": authority,
		"GENERATION_FLOOR":         fmt.Sprint(floor),
		"COUNT_FLOOR":              fmt.Sprint(count),
	}
	cfg, err := vault.LoadConfig(func(k string) string { return env[k] })
	if err != nil {
		c.t.Fatal(err)
	}
	return cfg
}

// node starts a Cloud vault, unrouted.
func (c *cloud) node(name, tag, authority string, floor, count uint64) *cloudNode {
	c.t.Helper()
	key := c.f.w.enroll(vaultRepo, name, tag)
	s := vault.NewServer(c.config(authority, floor, count), key, fakeAttester{name}, c.f.w, c.r.client())
	ts := httptest.NewTLSServer(s.Routes())
	c.t.Cleanup(ts.Close)
	n := &cloudNode{s: s, ts: ts}
	c.nodes[name] = n
	return n
}

func (c *cloud) post(base, path string, body any) (int, []byte) {
	c.t.Helper()
	var in []byte
	if body != nil {
		in, _ = json.Marshal(body)
	}
	resp, err := c.r.client().Post(base+path, "application/json", bytes.NewReader(in))
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// generateGeneration runs the generating release on name and returns it,
// holding the keyset and a new generation keyset.
func (c *cloud) generateGeneration(name, tag string, floor, count uint64) (*cloudNode, string) {
	c.t.Helper()
	gen := c.node(name, tag, "", floor, count)
	holder := c.f.committed[c.commitment]
	if err := gen.s.PullFrom(context.Background(), holder.url); err != nil {
		c.t.Fatalf("the generating release pulling the keyset: %v", err)
	}
	status, out := c.post(gen.ts.URL, "/generate-generation", nil)
	if status != http.StatusOK {
		c.t.Fatalf("generate-generation answered %d: %s", status, out)
	}
	var got struct {
		AuthorityKey string `json:"authority_key"`
	}
	json.Unmarshal(out, &got)
	return gen, got.AuthorityKey
}

// newCloud is the Cloud vault pair after its bootstrap: vault-a and vault-b
// on v0.3.0 committing to the generation keyset, register at the floors.
func newCloud(t *testing.T, floor, count uint64) *cloud {
	t.Helper()
	f := newFixture(t, 2, 1)
	c := &cloud{t: t, f: f, r: newRouter(t), nodes: map[string]*cloudNode{}}
	c.commitment, _ = f.bootstrap()
	gen, authority := c.generateGeneration("vault-a-gen", "v0.2.0", floor, count)
	c.authority = authority

	a := c.node("vault-a", "v0.3.0", authority, floor, count)
	if err := a.s.PullFrom(context.Background(), gen.ts.URL); err != nil {
		t.Fatalf("vault-a on the committed release: %v", err)
	}
	c.r.set(hostA, a.ts)
	b := c.node("vault-b", "v0.3.0", authority, floor, count)
	if err := b.s.PullFrom(context.Background(), "https://"+hostA); err != nil {
		t.Fatalf("vault-b pulling from vault-a: %v", err)
	}
	c.r.set(hostB, b.ts)
	return c
}

func (c *cloud) authorityKey() ed25519.PublicKey {
	k, err := wire.ParseAuthorityKey(c.authority)
	if err != nil {
		c.t.Fatal(err)
	}
	return k
}

// coordinator is one coordinator boot: its attested transfer key, and the
// generation the vault gave it.
type coordinator struct {
	name   string
	key    *ecdh.PrivateKey
	gen    ed25519.PrivateKey
	number uint64
	got    *wire.PullResult
}

func (c *cloud) enrollCoordinator(name string) *coordinator {
	return &coordinator{name: name, key: c.f.w.enroll(coordRepo, name, "v1.0.0")}
}

// boot is a coordinator's keyset pull from host that boots a generation.
func (c *cloud) boot(co *coordinator, host string) error {
	pub, priv, _ := ed25519.GenerateKey(nil)
	got, err := wire.PullBoot(context.Background(), c.r.client(), "https://"+host, co.key, fakeAttester{co.name}, nil, c.commitment, pub, c.authorityKey())
	if err != nil {
		return err
	}
	cert, err := wire.VerifyGenerationCertificate(got.GenerationCertificate, c.authorityKey())
	if err != nil {
		return err
	}
	co.gen, co.number, co.got = priv, cert.Generation, got
	return nil
}

func (c *cloud) mustBoot(name, host string) *coordinator {
	c.t.Helper()
	co := c.enrollCoordinator(name)
	if err := c.boot(co, host); err != nil {
		c.t.Fatalf("booting %s at %s: %v", name, host, err)
	}
	return co
}

func (c *cloud) counter(hosts ...string) *wire.CounterClient {
	var vaults []string
	for _, h := range hosts {
		vaults = append(vaults, "https://"+h)
	}
	return &wire.CounterClient{Vaults: vaults, Authority: c.authorityKey(), Client: c.r.client()}
}

func (c *cloud) load(host string) wire.CounterState {
	c.t.Helper()
	st, err := c.counter(host).Load(context.Background())
	if err != nil {
		c.t.Fatalf("load at %s: %v", host, err)
	}
	return st
}

func (c *cloud) cas(co *coordinator, host string, generation, prev, next uint64) error {
	_, err := c.counter(host).CompareAndSwap(context.Background(), co.gen, generation, prev, next)
	return err
}

// level checks both vaults hold the same head at want.
func (c *cloud) level(want wire.CounterState) {
	c.t.Helper()
	var versions []uint64
	for _, name := range []string{"vault-a", "vault-b"} {
		v, g, n, ok := c.nodes[name].s.RegisterHead()
		if !ok || g != want.Generation || n != want.Count {
			c.t.Fatalf("%s's register is at generation %d count %d (held %t), want %+v", name, g, n, ok, want)
		}
		versions = append(versions, v)
	}
	if versions[0] != versions[1] {
		c.t.Fatalf("the vaults are at versions %v", versions)
	}
}

func TestCloudGenerationsAndCounter(t *testing.T) {
	c := newCloud(t, 0, 0)
	if st := c.load(hostB); st != (wire.CounterState{Generation: 0, Count: 0}) {
		t.Fatalf("a new register loads %+v", st)
	}
	// No coordinator has booted, so nothing may swap.
	nobody := c.enrollCoordinator("nobody")
	_, nobody.gen, _ = ed25519.GenerateKey(nil)
	if err := c.cas(nobody, hostA, 1, 0, 1); !errors.Is(err, wire.ErrCounterGeneration) {
		t.Fatalf("a swap before any boot: %v", err)
	}

	gen1 := c.mustBoot("coordinator-1", hostA)
	if gen1.number != 1 {
		t.Fatalf("the first boot is generation %d", gen1.number)
	}
	if gen1.got.GenerationKeyset != nil || gen1.got.Register != nil {
		t.Fatal("a coordinator got the generation keyset or the register")
	}
	if err := c.cas(gen1, hostA, 1, 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := c.cas(gen1, hostB, 1, 1, 3); err != nil {
		t.Fatal(err)
	}
	c.level(wire.CounterState{Generation: 1, Count: 3})

	// A restore boots a new generation, through either vault. The count
	// stays.
	gen2 := c.mustBoot("coordinator-2", hostB)
	if gen2.number != 2 {
		t.Fatalf("the second boot is generation %d", gen2.number)
	}
	if st := c.load(hostA); st != (wire.CounterState{Generation: 2, Count: 3}) {
		t.Fatalf("after the second boot: %+v", st)
	}
	// The first generation is fenced.
	err := c.cas(gen1, hostA, 1, 3, 4)
	var refusal *wire.CounterRefusal
	if !errors.Is(err, wire.ErrCounterGeneration) || !errors.As(err, &refusal) || refusal.Result != wire.CounterStaleGeneration {
		t.Fatalf("generation 1 swapping after generation 2 booted: %v", err)
	}
	// Generation 1's key naming generation 2 isn't generation 2.
	if err := c.cas(gen1, hostA, 2, 3, 4); !errors.As(err, &refusal) || refusal.Result != wire.CounterBadSignature || !errors.Is(err, wire.ErrCounterGeneration) {
		t.Fatalf("generation 1's key naming generation 2: %v", err)
	}
	for _, bad := range [][2]uint64{{2, 4}, {3, 3}, {3, 2}} {
		if err := c.cas(gen2, hostA, 2, bad[0], bad[1]); !errors.Is(err, wire.ErrCounterCount) || !errors.As(err, &refusal) || refusal.State.Count != 3 {
			t.Fatalf("swap %d to %d at count 3: %v", bad[0], bad[1], err)
		}
	}
	if err := c.cas(gen2, hostB, 2, 3, 4); err != nil {
		t.Fatal(err)
	}
	c.level(wire.CounterState{Generation: 2, Count: 4})
}

func TestCloudCounterAnswersCantBeReplayed(t *testing.T) {
	c := newCloud(t, 0, 0)
	gen1 := c.mustBoot("coordinator-1", hostA)
	c.mustBoot("coordinator-2", hostA)

	// Capture a load's answer and a stale-generation refusal.
	nonce, _ := wire.RandomNonce()
	_, loadAnswer := c.post("https://"+hostA, wire.CounterPath, wire.CounterRequest{Op: wire.CounterLoad, Nonce: hex.EncodeToString(nonce)})
	cas := wire.CounterRequest{Op: wire.CounterCAS, Nonce: hex.EncodeToString(nonce), Generation: 1, Prev: 0, Next: 1,
		Signature: ed25519.Sign(gen1.gen, wire.CASMessage(nonce, 1, 0, 1))}
	status, staleAnswer := c.post("https://"+hostA, wire.CounterPath, cas)
	if status != http.StatusConflict || !strings.Contains(string(staleAnswer), wire.CounterStaleGeneration) {
		t.Fatalf("stale cas answered %d %s", status, staleAnswer)
	}

	replay := func(status int, body []byte) string {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			w.Write(body)
		}))
		t.Cleanup(ts.Close)
		return ts.URL
	}
	client := &wire.CounterClient{Vaults: []string{replay(http.StatusOK, loadAnswer)}, Authority: c.authorityKey(), Client: http.DefaultClient}
	if _, err := client.Load(context.Background()); !errors.Is(err, wire.ErrCounterUnavailable) {
		t.Fatalf("a replayed load answer: %v", err)
	}
	// A replayed refusal can't retire a coordinator either.
	client.Vaults = []string{replay(http.StatusConflict, staleAnswer)}
	if _, err := client.CompareAndSwap(context.Background(), gen1.gen, 1, 0, 1); !errors.Is(err, wire.ErrCounterUnavailable) || errors.Is(err, wire.ErrCounterGeneration) {
		t.Fatalf("a replayed refusal: %v", err)
	}
	// Nor can an answer signed by anyone but the authority.
	_, other, _ := ed25519.GenerateKey(nil)
	forger := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req wire.CounterRequest
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(wire.AnswerCounter(other, &req, wire.CounterOK, wire.CounterState{Generation: 9, Count: 0}))
	}))
	t.Cleanup(forger.Close)
	client.Vaults = []string{forger.URL}
	if _, err := client.Load(context.Background()); !errors.Is(err, wire.ErrCounterUnavailable) {
		t.Fatalf("a forged answer: %v", err)
	}
}

func TestCloudSwapRetriedAfterALostAnswer(t *testing.T) {
	c := newCloud(t, 0, 0)
	gen1 := c.mustBoot("coordinator-1", hostA)
	// A proxy that forwards the swap and loses the answer.
	lossy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := c.r.client().Post("https://"+hostA+r.URL.Path, "application/json", r.Body)
		if err == nil {
			resp.Body.Close()
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(lossy.Close)
	client := &wire.CounterClient{Vaults: []string{lossy.URL}, Authority: c.authorityKey(), Client: http.DefaultClient}
	if _, err := client.CompareAndSwap(context.Background(), gen1.gen, 1, 0, 1); !errors.Is(err, wire.ErrCounterUnavailable) {
		t.Fatalf("a lost answer: %v", err)
	}
	if st := c.load(hostB); st.Count != 1 {
		t.Fatalf("the lost swap didn't count: %+v", st)
	}
	if err := c.cas(gen1, hostB, 1, 0, 1); err != nil {
		t.Fatalf("retrying the lost swap: %v", err)
	}
	if err := c.cas(gen1, hostA, 1, 1, 2); err != nil {
		t.Fatal(err)
	}
	// Only the last swap is answered again.
	if err := c.cas(gen1, hostA, 1, 0, 1); !errors.Is(err, wire.ErrCounterCount) {
		t.Fatalf("retrying a swap that isn't the last: %v", err)
	}
	c.level(wire.CounterState{Generation: 1, Count: 2})
}

func TestCloudOneVaultDownRefusesEverything(t *testing.T) {
	c := newCloud(t, 0, 0)
	gen1 := c.mustBoot("coordinator-1", hostA)
	if err := c.cas(gen1, hostA, 1, 0, 1); err != nil {
		t.Fatal(err)
	}
	b := c.nodes["vault-b"]
	c.r.down(hostB)
	if _, err := c.counter(hostA).Load(context.Background()); !errors.Is(err, wire.ErrCounterUnavailable) {
		t.Fatalf("a load with vault-b down: %v", err)
	}
	if err := c.cas(gen1, hostA, 1, 1, 2); !errors.Is(err, wire.ErrCounterUnavailable) {
		t.Fatalf("a swap with vault-b down: %v", err)
	}
	if err := c.boot(c.enrollCoordinator("coordinator-2"), hostA); err == nil || !strings.Contains(err.Error(), "booting a generation") {
		t.Fatalf("a boot with vault-b down: %v", err)
	}
	// vault-a refuses rather than moving on alone.
	if _, g, n, _ := c.nodes["vault-a"].s.RegisterHead(); g != 1 || n != 1 {
		t.Fatalf("vault-a moved alone to generation %d count %d", g, n)
	}
	c.r.set(hostB, b.ts)
	if st := c.load(hostA); st != (wire.CounterState{Generation: 1, Count: 1}) {
		t.Fatalf("back up: %+v", st)
	}
	if err := c.cas(gen1, hostA, 1, 1, 2); err != nil {
		t.Fatal(err)
	}
	c.level(wire.CounterState{Generation: 1, Count: 2})
}

func TestCloudChangeCutShortIsFinished(t *testing.T) {
	for _, ahead := range []string{"vault-a", "vault-b"} {
		t.Run(ahead, func(t *testing.T) {
			c := newCloud(t, 0, 0)
			gen1 := c.mustBoot("coordinator-1", hostA)
			// One vault took a change the other never got: the first vault
			// of a change cut short, or the survivor when the other was
			// promoted from a stale candidate.
			if res, err := c.nodes[ahead].s.ForceRegisterSwap(5); err != nil || res != "accepted" {
				t.Fatal(res, err)
			}
			if st := c.load(hostA); st != (wire.CounterState{Generation: 1, Count: 5}) {
				t.Fatalf("load after a change cut short: %+v", st)
			}
			c.level(wire.CounterState{Generation: 1, Count: 5})
			// The coordinator takes a count ahead of its own as its lost
			// answer, and goes on.
			if err := c.cas(gen1, hostB, 1, 5, 6); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCloudDivergedRegistersRefuseUntilARestart(t *testing.T) {
	c := newCloud(t, 0, 0)
	gen1 := c.mustBoot("coordinator-1", hostA)
	c.nodes["vault-a"].s.ForceRegisterSwap(5)
	c.nodes["vault-b"].s.ForceRegisterSwap(6)
	if _, err := c.counter(hostA, hostB).Load(context.Background()); !errors.Is(err, wire.ErrCounterUnavailable) || !strings.Contains(err.Error(), "diverged") {
		t.Fatalf("a load with the vaults diverged: %v", err)
	}
	if err := c.cas(gen1, hostB, 1, 6, 7); !errors.Is(err, wire.ErrCounterUnavailable) {
		t.Fatalf("a swap with the vaults diverged: %v", err)
	}
	// Restarting vault-b: it pulls vault-a's register with the keyset.
	b2 := c.node("vault-b-2", "v0.3.0", c.authority, 0, 0)
	if err := b2.s.PullFrom(context.Background(), "https://"+hostA); err != nil {
		t.Fatal(err)
	}
	c.r.set(hostB, b2.ts)
	c.nodes["vault-b"] = b2
	if st := c.load(hostB); st != (wire.CounterState{Generation: 1, Count: 5}) {
		t.Fatalf("after restarting vault-b: %+v", st)
	}
	if err := c.cas(gen1, hostB, 1, 5, 6); err != nil {
		t.Fatal(err)
	}
}

func TestCloudPromotedCandidateDoesntRollBack(t *testing.T) {
	c := newCloud(t, 0, 0)
	gen1 := c.mustBoot("coordinator-1", hostA)
	if err := c.cas(gen1, hostA, 1, 0, 1); err != nil {
		t.Fatal(err)
	}
	// vault-a is upgraded: its held candidate pulls from production.
	cand := c.node("vault-a-next", "v0.3.1", c.authority, 0, 0)
	if err := cand.s.PullFrom(context.Background(), "https://"+hostA); err != nil {
		t.Fatal(err)
	}
	// Changes go on while it's held, and it's promoted without syncing.
	if err := c.cas(gen1, hostB, 1, 1, 2); err != nil {
		t.Fatal(err)
	}
	if _, _, n, _ := cand.s.RegisterHead(); n != 1 {
		t.Fatalf("the candidate is at count %d", n)
	}
	c.r.set(hostA, cand.ts)
	c.nodes["vault-a"] = cand
	if st := c.load(hostA); st != (wire.CounterState{Generation: 1, Count: 2}) {
		t.Fatalf("after promoting a stale candidate: %+v", st)
	}
	c.level(wire.CounterState{Generation: 1, Count: 2})
	// Now vault-b restarts, and pulls from the promoted vault-a.
	b2 := c.node("vault-b-2", "v0.3.1", c.authority, 0, 0)
	if err := b2.s.PullFrom(context.Background(), "https://"+hostA); err != nil {
		t.Fatal(err)
	}
	c.r.set(hostB, b2.ts)
	c.nodes["vault-b"] = b2
	c.level(wire.CounterState{Generation: 1, Count: 2})
}

func TestCloudHeldCandidateFollowsProduction(t *testing.T) {
	c := newCloud(t, 0, 0)
	gen1 := c.mustBoot("coordinator-1", hostA)
	cand := c.node("vault-b-next", "v0.3.1", c.authority, 0, 0)
	if err := cand.s.PullFrom(context.Background(), "https://"+hostB); err != nil {
		t.Fatal(err)
	}
	if err := c.cas(gen1, hostA, 1, 0, 7); err != nil {
		t.Fatal(err)
	}
	if err := cand.s.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, n, _ := cand.s.RegisterHead(); n != 7 {
		t.Fatalf("the held candidate's sync left it at count %d", n)
	}
	// A candidate handles a call like any vault: it reads both production
	// vaults.
	ts := cand.ts
	client := &wire.CounterClient{Vaults: []string{ts.URL}, Authority: c.authorityKey(), Client: c.r.client()}
	if st, err := client.Load(context.Background()); err != nil || st.Count != 7 {
		t.Fatalf("a load at the candidate: %+v %v", st, err)
	}
}

func TestCloudFloorsStartTheRegister(t *testing.T) {
	c := newCloud(t, 41, 12)
	if st := c.load(hostA); st != (wire.CounterState{Generation: 41, Count: 12}) {
		t.Fatalf("a register after a total loss: %+v", st)
	}
	if co := c.mustBoot("coordinator-1", hostA); co.number != 42 {
		t.Fatalf("the first boot after the floor is %d", co.number)
	}
	// A release whose floors are above the register refuses it.
	high := c.node("vault-b-high", "v0.3.1", c.authority, 100, 0)
	if err := high.s.PullFrom(context.Background(), "https://"+hostA); err == nil || !strings.Contains(err.Error(), "below this release's floors") {
		t.Fatalf("a release with higher floors took the register: %v", err)
	}
}

func TestCloudKeepsTheGenerationKeysetFromCoordinators(t *testing.T) {
	c := newCloud(t, 0, 0)
	co := c.enrollCoordinator("coordinator-1")
	// A pull without a boot, as a restore dry run makes: the keyset, and the
	// generation stays.
	got, err := wire.PullKeysets(context.Background(), c.r.client(), "https://"+hostA, co.key, fakeAttester{co.name}, nil,
		wire.Commitments{Keyset: c.commitment, Generation: c.authority})
	if err != nil {
		t.Fatal(err)
	}
	if got.GenerationKeyset != nil || got.Register != nil || got.GenerationCertificate != "" {
		t.Fatalf("a coordinator's pull got %+v", got)
	}
	if st := c.load(hostA); st.Generation != 0 {
		t.Fatalf("a pull without a boot moved the generation to %d", st.Generation)
	}
}

func TestCloudBootIsBoundToTheAttestation(t *testing.T) {
	c := newCloud(t, 0, 0)
	co := c.enrollCoordinator("coordinator-1")
	finish := func(attested func(issued []byte) []byte, key []byte, a fakeAttester) (int, string) {
		var begun wire.BeginResponse
		if err := wire.PostJSON(context.Background(), c.r.client(), "https://"+hostA+"/transfer/begin", nil, &begun); err != nil {
			t.Fatal(err)
		}
		issued, _ := wire.DecodeNonce(begun.Nonce)
		answer, _ := wire.RandomNonce()
		doc, _ := a.Attest(context.Background(), attested(issued))
		status, out := c.post("https://"+hostA, "/transfer/finish", wire.FinishRequest{Nonce: begun.Nonce, AnswerNonce: hex.EncodeToString(answer), Document: doc, CoordinatorKey: key})
		return status, string(out)
	}
	// Someone in the middle swaps the coordinator's key: the document was
	// for the coordinator's own.
	mine, _, _ := ed25519.GenerateKey(nil)
	theirs, _, _ := ed25519.GenerateKey(nil)
	status, out := finish(func(issued []byte) []byte { return wire.BootNonce(issued, mine) }, theirs, fakeAttester{co.name})
	if status != http.StatusForbidden || !strings.Contains(out, "refused at verify") {
		t.Fatalf("a swapped coordinator key: %d %s", status, out)
	}
	// A document for the plain nonce doesn't vouch for any key.
	status, out = finish(func(issued []byte) []byte { return issued }, mine, fakeAttester{co.name})
	if status != http.StatusForbidden || !strings.Contains(out, "refused at verify") {
		t.Fatalf("a boot whose document names no key: %d %s", status, out)
	}
	// A vault doesn't boot a generation.
	c.f.w.enroll(vaultRepo, "vault-c", "v0.3.0")
	status, out = finish(func(issued []byte) []byte { return wire.BootNonce(issued, mine) }, mine, fakeAttester{"vault-c"})
	if status != http.StatusForbidden || !strings.Contains(out, "refused at boot") {
		t.Fatalf("a vault asking for a boot: %d %s", status, out)
	}
	if st := c.load(hostA); st.Generation != 0 {
		t.Fatalf("a refused boot moved the generation to %d", st.Generation)
	}
}

// The review's C1 probe: an outsider with a genuine coordinator's document
// for BootNonce(N, their key), fetched from its public attestation endpoint,
// but not its transfer key. Before the boot proof this booted a generation
// for the outsider's key, who then swapped the count to 2^64-1.
func TestCloudBootNeedsTheTransferKey(t *testing.T) {
	c := newCloud(t, 0, 0)
	prod := c.mustBoot("coordinator-prod", hostA)
	if err := c.cas(prod, hostA, 1, 0, 1); err != nil {
		t.Fatal(err)
	}
	attackerPub, attackerPriv, _ := ed25519.GenerateKey(nil)
	attackerTransfer, _ := ecdh.X25519().GenerateKey(rand.Reader)
	public := fakeAttester{prod.name} // the prod coordinator's public endpoint
	for name, prove := range map[string]func(begun wire.BeginResponse, n wire.Nonces) []byte{
		"no proof": func(wire.BeginResponse, wire.Nonces) []byte { return nil },
		"junk proof": func(wire.BeginResponse, wire.Nonces) []byte {
			return bytes.Repeat([]byte{7}, 32)
		},
		// The best an outsider can do: an agreement with its own key, which
		// isn't the one the document endorses.
		"proof under the outsider's own key": func(begun wire.BeginResponse, n wire.Nonces) []byte {
			holder, _ := wire.ParseRawKey(begun.HolderKey)
			proof, _ := wire.BootProof(attackerTransfer, holder, attackerTransfer.PublicKey(), holder, n, attackerPub)
			return proof
		},
		// The coordinator's public key in place of its private one.
		"proof naming the coordinator's key": func(begun wire.BeginResponse, n wire.Nonces) []byte {
			holder, _ := wire.ParseRawKey(begun.HolderKey)
			proof, _ := wire.BootProof(attackerTransfer, holder, prod.key.PublicKey(), holder, n, attackerPub)
			return proof
		},
	} {
		t.Run(name, func(t *testing.T) {
			var begun wire.BeginResponse
			if err := wire.PostJSON(context.Background(), c.r.client(), "https://"+hostA+"/transfer/begin", nil, &begun); err != nil {
				t.Fatal(err)
			}
			issued, _ := wire.DecodeNonce(begun.Nonce)
			answer, _ := wire.RandomNonce()
			doc, _ := public.Attest(context.Background(), wire.BootNonce(issued, attackerPub))
			status, out := c.post("https://"+hostA, "/transfer/finish", wire.FinishRequest{
				Nonce: begun.Nonce, AnswerNonce: hex.EncodeToString(answer), Document: doc, CoordinatorKey: attackerPub,
				BootProof: prove(begun, wire.Nonces{Issued: issued, Answer: answer})})
			if status != http.StatusForbidden || !strings.Contains(string(out), "refused at boot proof") {
				t.Fatalf("an outsider's boot answered %d: %s", status, out)
			}
			c.level(wire.CounterState{Generation: 1, Count: 1})
			outsider := &coordinator{gen: attackerPriv}
			if err := c.cas(outsider, hostA, 2, 1, 1<<63); !errors.Is(err, wire.ErrCounterGeneration) {
				t.Fatalf("the outsider's swap: %v", err)
			}
		})
	}
	// The prod coordinator is still the live one, and its next boot works.
	if err := c.cas(prod, hostB, 1, 1, 2); err != nil {
		t.Fatalf("prod after the outsider's boots: %v", err)
	}
	if next := c.mustBoot("coordinator-prod", hostB); next.number != 2 {
		t.Fatalf("prod's next boot is generation %d", next.number)
	}
}

func TestCloudConcurrentSwapsDontFork(t *testing.T) {
	c := newCloud(t, 0, 0)
	gen1 := c.mustBoot("coordinator-1", hostA)
	prev := uint64(0)
	for round := range 8 {
		results := make([]error, 2)
		var wg sync.WaitGroup
		for i, host := range []string{hostA, hostB} {
			wg.Go(func() { results[i] = c.cas(gen1, host, 1, prev, prev+1+uint64(i)) })
		}
		wg.Wait()
		won := -1
		for i, err := range results {
			if err == nil {
				if won >= 0 {
					t.Fatalf("round %d: both swaps from %d succeeded", round, prev)
				}
				won = i
			}
		}
		st := c.load(hostA)
		if won >= 0 && st.Count != prev+1+uint64(won) {
			t.Fatalf("round %d: swap %d won and the count is %d", round, won, st.Count)
		}
		// With neither answered, one may still have committed, as a lost
		// answer would; the count is then one of the two, never anything
		// else.
		if st.Count != prev && st.Count != prev+1 && st.Count != prev+2 {
			t.Fatalf("round %d: the count is %d after swaps from %d", round, st.Count, prev)
		}
		c.level(wire.CounterState{Generation: 1, Count: st.Count})
		prev = st.Count
	}
}

func TestMailVaultRefusesCloudCalls(t *testing.T) {
	f := newFixture(t, 2, 1)
	commitment, v := f.bootstrap()
	if status, _ := v.post(t, "/generate-generation"); status != http.StatusConflict {
		t.Fatalf("a mail vault's generate-generation answered %d", status)
	}
	if status, _ := v.post(t, wire.CounterPath); status != http.StatusConflict {
		t.Fatalf("a mail vault's counter answered %d", status)
	}
	e := f.edge("edge", "v1.0.0")
	pub, _, _ := ed25519.GenerateKey(nil)
	_, err := wire.PullBoot(context.Background(), http.DefaultClient, v.url, e.key, e.a, nil, commitment, pub, pub)
	if err == nil || !strings.Contains(err.Error(), "refused at boot") {
		t.Fatalf("a mail vault booting a generation: %v", err)
	}
	// A mail edge's ordinary pull is as it was.
	if _, err := e.pull(v.url, commitment); err != nil {
		t.Fatal(err)
	}
}

func TestCloudConfig(t *testing.T) {
	f := newFixture(t, 1, 1)
	base := map[string]string{
		"VAULT_REPO": vaultRepo, "EDGE_REPO": coordRepo, "EDGE_MIN_TAG": "v1.0.0",
		"KEYSET_COMMITMENT":   strings.Repeat("ab", 32),
		"VAULT_PEERS":         hostA + "," + hostB,
		"RECOVERY_RECIPIENTS": f.ids[0].Recipient().String(), "RECOVERY_THRESHOLD": "1",
		"OPERATOR_KEY":     hex.EncodeToString(f.operator.Public().(ed25519.PublicKey)),
		"COORDINATOR_MODE": "1", "GENERATION_FLOOR": "0", "COUNT_FLOOR": "0",
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	g := &wire.GenerationKeyset{}
	copy(g.Seed[:], pub)
	for name, change := range map[string]map[string]string{
		"no floors":              {"GENERATION_FLOOR": "", "COUNT_FLOOR": ""},
		"bad floor":              {"COUNT_FLOOR": "-1"},
		"one peer":               {"VAULT_PEERS": hostA},
		"bad mode":               {"COORDINATOR_MODE": "yes"},
		"bad authority":          {"GENERATION_AUTHORITY_KEY": "abc"},
		"authority, no keyset":   {"GENERATION_AUTHORITY_KEY": g.AuthorityKey(), "KEYSET_COMMITMENT": ""},
		"floors on a mail vault": {"COORDINATOR_MODE": ""},
	} {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		for k, v := range change {
			env[k] = v
		}
		if _, err := vault.LoadConfig(func(k string) string { return env[k] }); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	env := map[string]string{}
	for k, v := range base {
		env[k] = v
	}
	env["GENERATION_AUTHORITY_KEY"] = g.AuthorityKey()
	cfg, err := vault.LoadConfig(func(k string) string { return env[k] })
	if err != nil || !cfg.CoordinatorMode || cfg.GenerationKey != g.AuthorityKey() {
		t.Fatalf("%+v %v", cfg, err)
	}
}
