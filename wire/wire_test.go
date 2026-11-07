package wire

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"
)

func generate(t *testing.T) *Keyset {
	t.Helper()
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeysetRoundTrips(t *testing.T) {
	k := generate(t)
	parsed, err := ParseKeyset(k.MarshalBinary())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.MarshalBinary(), k.MarshalBinary()) || !parsed.Matches(k.Commitment()) {
		t.Fatal("keyset changed in a round trip")
	}
}

func TestParseKeysetRejectsOtherEncodings(t *testing.T) {
	good := generate(t).MarshalBinary()
	wrongVersion := bytes.Clone(good)
	wrongVersion[0] = 2
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(p384)
	if err != nil {
		t.Fatal(err)
	}
	wrongCurve := (&Keyset{ACMEAccountKey: der}).MarshalBinary()

	for name, b := range map[string][]byte{
		"trailing byte": append(bytes.Clone(good), 0),
		"truncated":     good[:len(good)-1],
		"empty":         nil,
		"version":       wrongVersion,
		"P-384":         wrongCurve,
	} {
		if _, err := ParseKeyset(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// The edge and the vault must agree on this forever, because releases pin it.
// The value was computed separately, in Python, from the encoding described above.
func TestCommitmentIsStable(t *testing.T) {
	var k Keyset
	for i := range k.AddressMACKey {
		k.AddressMACKey[i] = byte(i)
		k.RoutingDataKey[i] = byte(0xff - i)
	}
	k.ACMEAccountKey = []byte{0x30, 0x00}
	const want = "d248b1bb1c059f1b536dddedb367959691849e2d5b86ebef7c93caf1683dafa0"
	if got := k.Commitment(); got != want {
		t.Fatalf("commitment changed: got %s", got)
	}
}

func TestCommitmentCoversEveryKey(t *testing.T) {
	k := generate(t)
	base := k.Commitment()
	mac := *k
	mac.AddressMACKey[0] ^= 1
	routing := *k
	routing.RoutingDataKey[31] ^= 1
	acme := *k
	acme.ACMEAccountKey = bytes.Clone(k.ACMEAccountKey)
	acme.ACMEAccountKey[len(acme.ACMEAccountKey)-1] ^= 1
	for name, changed := range map[string]*Keyset{"mac": &mac, "routing": &routing, "acme": &acme} {
		if changed.Matches(base) {
			t.Errorf("changing the %s key kept the commitment", name)
		}
	}
}

func TestValidateCommitment(t *testing.T) {
	if err := ValidateCommitment(generate(t).Commitment()); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("A", 64), strings.Repeat("0", 63)} {
		if ValidateCommitment(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func newKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func nonces(t *testing.T) Nonces {
	t.Helper()
	a, err := RandomNonce()
	if err != nil {
		t.Fatal(err)
	}
	b, err := RandomNonce()
	if err != nil {
		t.Fatal(err)
	}
	return Nonces{Issued: a, Answer: b}
}

func TestBoxOpensOnlyForItsExchange(t *testing.T) {
	sender, recipient, stranger := newKey(t), newKey(t), newKey(t)
	n := nonces(t)
	box, err := Seal(PurposeKeyset, sender, recipient.PublicKey(), n, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(PurposeKeyset, recipient, sender.PublicKey(), n, box); err != nil || string(got) != "secret" {
		t.Fatalf("recipient couldn't open: %q, %v", got, err)
	}

	tampered := bytes.Clone(box)
	tampered[len(tampered)-1] ^= 1
	other := nonces(t)
	cases := map[string]func() ([]byte, error){
		"stranger":      func() ([]byte, error) { return Open(PurposeKeyset, stranger, sender.PublicKey(), n, box) },
		"wrong sender":  func() ([]byte, error) { return Open(PurposeKeyset, recipient, stranger.PublicKey(), n, box) },
		"other purpose": func() ([]byte, error) { return Open(PurposeShare, recipient, sender.PublicKey(), n, box) },
		"issued nonce": func() ([]byte, error) {
			return Open(PurposeKeyset, recipient, sender.PublicKey(), Nonces{Issued: other.Issued, Answer: n.Answer}, box)
		},
		"answer nonce": func() ([]byte, error) {
			return Open(PurposeKeyset, recipient, sender.PublicKey(), Nonces{Issued: n.Issued, Answer: other.Answer}, box)
		},
		"altered": func() ([]byte, error) { return Open(PurposeKeyset, recipient, sender.PublicKey(), n, tampered) },
	}
	for name, open := range cases {
		if _, err := open(); err == nil {
			t.Errorf("%s opened the box", name)
		}
	}
}

func TestBoxRejectsShortNonces(t *testing.T) {
	sender, recipient := newKey(t), newKey(t)
	if _, err := Seal(PurposeKeyset, sender, recipient.PublicKey(), Nonces{Issued: []byte("x"), Answer: []byte("y")}, nil); err == nil {
		t.Fatal("sealed with short nonces")
	}
}
