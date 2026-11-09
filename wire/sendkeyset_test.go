package wire

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

var (
	sendOnce sync.Once
	sendKeys *SendKeyset
	sendErr  error
)

// generateSend reuses one send keyset, because RSA keygen is slow under -race.
func generateSend(t *testing.T) *SendKeyset {
	t.Helper()
	sendOnce.Do(func() { sendKeys, sendErr = GenerateSend() })
	if sendErr != nil {
		t.Fatal(sendErr)
	}
	return sendKeys
}

func TestSendKeysetRoundTrips(t *testing.T) {
	k := generateSend(t)
	parsed, err := ParseSendKeyset(k.MarshalBinary())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.MarshalBinary(), k.MarshalBinary()) || !parsed.Matches(k.Commitment()) {
		t.Fatal("send keyset changed in a round trip")
	}
	rsaKey, err := parsed.DKIMRSA()
	if err != nil || rsaKey.N.BitLen() != 2048 {
		t.Fatalf("RSA DKIM key: %v", err)
	}
	if _, err := parsed.DKIMEd25519(); err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.RelayClient(); err != nil {
		t.Fatal(err)
	}
}

func pkcs8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseSendKeysetRejectsOtherEncodings(t *testing.T) {
	k := generateSend(t)
	good := k.MarshalBinary()
	wrongVersion := bytes.Clone(good)
	wrongVersion[0] = 2
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	with := func(edit func(*SendKeyset)) []byte {
		c := *k
		edit(&c)
		return c.MarshalBinary()
	}
	for name, b := range map[string][]byte{
		"trailing byte":   append(bytes.Clone(good), 0),
		"truncated":       good[:len(good)-1],
		"empty":           nil,
		"version only":    {1},
		"version":         wrongVersion,
		"mail keyset":     generate(t).MarshalBinary(),
		"RSA-1024":        with(func(c *SendKeyset) { c.DKIMRSAKey = pkcs8(t, rsa1024) }),
		"ECDSA for RSA":   with(func(c *SendKeyset) { c.DKIMRSAKey = pkcs8(t, p256) }),
		"RSA for Ed25519": with(func(c *SendKeyset) { c.DKIMEd25519Key = k.DKIMRSAKey }),
		"RSA for relay":   with(func(c *SendKeyset) { c.RelayClientKey = k.DKIMRSAKey }),
		"shared Ed25519":  with(func(c *SendKeyset) { c.RelayClientKey = k.DKIMEd25519Key }),
		"missing relay":   with(func(c *SendKeyset) { c.RelayClientKey = nil }),
	} {
		if _, err := ParseSendKeyset(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// The edge and the vault must agree on this forever, because releases pin it.
// The value was computed separately, in Python, from the encoding described on
// MarshalBinary. The RSA field is 0x0123 bytes long, so a little-endian length
// would fail too:
//
//	import hashlib, struct
//	keys = (bytes(i % 256 for i in range(0x123)), bytes(0xff - i for i in range(48)), b"\x30\x00")
//	enc = b"\x01" + b"".join(struct.pack(">H", len(k)) + k for k in keys)
//	print(hashlib.sha256(b"fount-mail-send-keyset/v1" + enc).hexdigest())
func TestSendCommitmentIsStable(t *testing.T) {
	var k SendKeyset
	for i := range 0x123 {
		k.DKIMRSAKey = append(k.DKIMRSAKey, byte(i))
	}
	for i := range 48 {
		k.DKIMEd25519Key = append(k.DKIMEd25519Key, byte(0xff-i))
	}
	k.RelayClientKey = []byte{0x30, 0x00}
	if n := len(k.MarshalBinary()); n != 348 {
		t.Fatalf("encoding is %d bytes, want 348", n)
	}
	const want = "05e3e3f666e16dad7ccac6219fa486fe63c6fab4ded170478954fd70df7e393c"
	if got := k.Commitment(); got != want {
		t.Fatalf("send commitment changed: got %s", got)
	}
}

func TestSendCommitmentCoversEveryKeyAndItsDomain(t *testing.T) {
	k := generateSend(t)
	base := k.Commitment()
	flip := func(b []byte) []byte {
		c := bytes.Clone(b)
		c[len(c)-1] ^= 1
		return c
	}
	for name, changed := range map[string]SendKeyset{
		"rsa":   {DKIMRSAKey: flip(k.DKIMRSAKey), DKIMEd25519Key: k.DKIMEd25519Key, RelayClientKey: k.RelayClientKey},
		"ed":    {DKIMRSAKey: k.DKIMRSAKey, DKIMEd25519Key: flip(k.DKIMEd25519Key), RelayClientKey: k.RelayClientKey},
		"relay": {DKIMRSAKey: k.DKIMRSAKey, DKIMEd25519Key: k.DKIMEd25519Key, RelayClientKey: flip(k.RelayClientKey)},
	} {
		if changed.Matches(base) {
			t.Errorf("changing the %s key kept the send commitment", name)
		}
	}
	if err := ValidateCommitment(base); err != nil {
		t.Fatal(err)
	}
	// The same bytes under the mail keyset's domain must commit differently.
	var mail Keyset
	if mail.Commitment() == (&SendKeyset{}).Commitment() {
		t.Fatal("the two commitment domains collide")
	}
}

// holder seals a payload the way a vault does, with no checks of its own. It
// returns its URL, the requester's key, and a HolderCheck that endorses it.
func holder(t *testing.T, payload Payload) (string, *ecdh.PrivateKey, HolderCheck) {
	t.Helper()
	key, requester := newKey(t), newKey(t)
	var issued []byte
	mux := http.NewServeMux()
	mux.HandleFunc("POST /transfer/begin", func(w http.ResponseWriter, _ *http.Request) {
		issued, _ = RandomNonce()
		json.NewEncoder(w).Encode(BeginResponse{Nonce: hex.EncodeToString(issued)})
	})
	mux.HandleFunc("POST /transfer/finish", func(w http.ResponseWriter, r *http.Request) {
		var req FinishRequest
		json.NewDecoder(r.Body).Decode(&req)
		answer, _ := DecodeNonce(req.AnswerNonce)
		plaintext, _ := json.Marshal(payload)
		sealed, err := Seal(PurposeKeyset, key, requester.PublicKey(), Nonces{Issued: issued, Answer: answer}, plaintext)
		if err != nil {
			t.Error(err)
		}
		json.NewEncoder(w).Encode(FinishResponse{HolderKey: key.PublicKey().Bytes(), Sealed: sealed})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts.URL, requester, func(_, _ []byte) (*ecdh.PublicKey, error) { return key.PublicKey(), nil }
}

type nullAttester struct{}

func (nullAttester) Attest(context.Context, []byte) ([]byte, error) { return []byte("doc"), nil }

func TestPullKeysetsChecksTheSendCommitment(t *testing.T) {
	mail, send := generate(t), generateSend(t)
	other := *send
	_, otherRelay, _ := ed25519.GenerateKey(rand.Reader)
	other.RelayClientKey = pkcs8(t, otherRelay)
	both := Commitments{Keyset: mail.Commitment(), Send: send.Commitment()}
	mailOnly := Commitments{Keyset: mail.Commitment()}
	withSend := func(b []byte) Payload { return Payload{Keyset: mail.MarshalBinary(), SendKeyset: b} }

	for _, c := range []struct {
		name     string
		payload  Payload
		verified bool
		want     Commitments
		wantSend string // the commitment of the send keyset returned, or ""
		wantErr  string
	}{
		{"send commitment, matching", withSend(send.MarshalBinary()), false, both, send.Commitment(), ""},
		{"send commitment, holder has none", withSend(nil), false, both, "", ""},
		{"send commitment, another send keyset", withSend(other.MarshalBinary()), false, both, "", "doesn't match the send commitment"},
		{"send commitment, malformed", withSend([]byte{1, 2}), false, both, "", "send keyset is truncated"},
		{"no send commitment, unverified holder", withSend(other.MarshalBinary()), false, mailOnly, "", ""},
		{"no send commitment, verified holder", withSend(other.MarshalBinary()), true, mailOnly, other.Commitment(), ""},
		{"no send commitment, verified holder, malformed", withSend([]byte{1, 2}), true, mailOnly, "", "send keyset is truncated"},
	} {
		url, me, endorse := holder(t, c.payload)
		var check HolderCheck
		if c.verified {
			check = endorse
		}
		got, err := PullKeysets(context.Background(), http.DefaultClient, url, me, nullAttester{}, check, c.want)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s: got %v, want an error with %q", c.name, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		gotSend := ""
		if got.SendKeyset != nil {
			gotSend = got.SendKeyset.Commitment()
		}
		if gotSend != c.wantSend || !got.Keyset.Matches(mail.Commitment()) {
			t.Errorf("%s: send keyset %q, want %q", c.name, gotSend, c.wantSend)
		}
	}
}

// Pull is what edge v0.2.1 and vault v0.1.2 call. It must ignore the send keyset
// entirely, even a malformed one, so a newer vault can't break them.
func TestPullIgnoresTheSendKeyset(t *testing.T) {
	mail := generate(t)
	for _, send := range [][]byte{generateSend(t).MarshalBinary(), {1, 2}} {
		url, me, endorse := holder(t, Payload{Keyset: mail.MarshalBinary(), SendKeyset: send})
		for _, check := range []HolderCheck{nil, endorse} {
			got, err := Pull(context.Background(), http.DefaultClient, url, me, nullAttester{}, check, mail.Commitment())
			if err != nil || got.SendKeyset != nil {
				t.Errorf("Pull with a send keyset: %v, %v", got, err)
			}
		}
	}
}

// v0.2.1's Payload has no send_keyset, and decoding a new payload into it must
// still work: encoding/json drops unknown fields.
func TestOldPayloadDecodesANewOne(t *testing.T) {
	type v021Payload struct {
		Keyset []byte         `json:"keyset"`
		S3     *S3Credentials `json:"s3,omitempty"`
	}
	raw, err := json.Marshal(Payload{Keyset: []byte{1}, S3: &S3Credentials{AccessKeyID: "a"}, SendKeyset: []byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	var old v021Payload
	if err := json.Unmarshal(raw, &old); err != nil || !bytes.Equal(old.Keyset, []byte{1}) || old.S3.AccessKeyID != "a" {
		t.Fatalf("old payload: %+v, %v", old, err)
	}
	if raw, _ := json.Marshal(Payload{Keyset: []byte{1}}); strings.Contains(string(raw), "send_keyset") {
		t.Fatalf("a payload with no send keyset still names the field: %s", raw)
	}
}
