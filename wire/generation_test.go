package wire

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
)

func fixedAuthority() *GenerationKeyset {
	g := &GenerationKeyset{}
	for i := range g.Seed {
		g.Seed[i] = byte(i)
	}
	return g
}

func TestGenerationKeysetRoundTrip(t *testing.T) {
	g := fixedAuthority()
	back, err := ParseGenerationKeyset(g.MarshalBinary())
	if err != nil || back.Seed != g.Seed {
		t.Fatal(err)
	}
	if _, err := ParseGenerationKeyset(append([]byte{2}, g.Seed[:]...)); err == nil {
		t.Fatal("parsed another version")
	}
	if !g.Matches(g.AuthorityKey()) || g.Matches(GenerationKeyset{}.authorityKeyForTest()) || g.Matches("nope") {
		t.Fatal("Matches")
	}
}

func (k GenerationKeyset) authorityKeyForTest() string { return k.AuthorityKey() }

// The certificate is the mail edge's (internal/generation), byte for byte:
// the vector is the edge's generation.Sign over the same inputs.
func TestGenerationCertificateVector(t *testing.T) {
	g := fixedAuthority()
	key := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	cert, err := SignGenerationCertificate(g.Authority(), GenerationCertificate{Generation: 7, CoordinatorKey: key, IssuedAt: 1})
	if err != nil {
		t.Fatal(err)
	}
	const edge = "eyJnZW5lcmF0aW9uIjo3LCJjb29yZGluYXRvcl9rZXkiOiJPMm9udk02MnBDMWlvNmpRS204TmMyVXlGWGNkNGtPbU9zQklvWXRaMmlrPSIsImlzc3VlZF9hdCI6MX0.Gi_sbadfKrMWjLBdHkl7Kzl8qwn2OFyjpQBT7rMA5LITXHSO64GS2ijCaz7Zh3uCUruBmGSJpchTb-CspoLTDw"
	if cert != edge {
		t.Fatalf("the certificate isn't the edge's: %s", cert)
	}
	c, err := VerifyGenerationCertificate(cert, g.Public())
	if err != nil || c.Generation != 7 || !key.Equal(ed25519.PublicKey(c.CoordinatorKey)) {
		t.Fatal(c, err)
	}
	other := &GenerationKeyset{}
	if _, err := VerifyGenerationCertificate(cert, other.Public()); err == nil {
		t.Fatal("verified under another authority")
	}
	if _, err := SignGenerationCertificate(g.Authority(), GenerationCertificate{Generation: 0, CoordinatorKey: key}); err == nil {
		t.Fatal("signed generation 0")
	}
}

func TestBootNonceBindsTheKey(t *testing.T) {
	issued := make([]byte, NonceSize)
	a, b := make([]byte, 32), make([]byte, 32)
	b[0] = 1
	if hex.EncodeToString(BootNonce(issued, a)) == hex.EncodeToString(BootNonce(issued, b)) {
		t.Fatal("the boot nonce doesn't depend on the key")
	}
	if len(BootNonce(issued, a)) != NonceSize {
		t.Fatal("the boot nonce isn't a nonce")
	}
}

func TestCounterAnswerIsBoundToItsRequest(t *testing.T) {
	g := fixedAuthority()
	n1, _ := RandomNonce()
	n2, _ := RandomNonce()
	r1 := &CounterRequest{Op: CounterLoad, Nonce: hex.EncodeToString(n1)}
	r2 := &CounterRequest{Op: CounterLoad, Nonce: hex.EncodeToString(n2)}
	a := AnswerCounter(g.Authority(), r1, CounterOK, CounterState{Generation: 3, Count: 9})
	if err := VerifyCounterAnswer(g.Public(), r1, &a); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCounterAnswer(g.Public(), r2, &a); err == nil {
		t.Fatal("an answer verified for another request")
	}
	a.Count = 10
	if err := VerifyCounterAnswer(g.Public(), r1, &a); err == nil {
		t.Fatal("an altered answer verified")
	}
	for _, bad := range []CounterRequest{
		{Op: CounterLoad, Nonce: r1.Nonce, Next: 1},
		{Op: CounterCAS, Nonce: r1.Nonce, Generation: 1},
		{Op: "store", Nonce: r1.Nonce},
		{Op: CounterLoad, Nonce: "00"},
	} {
		if _, err := bad.Validate(); err == nil {
			t.Fatalf("%+v validated", bad)
		}
	}
	ref := &CounterRefusal{Result: CounterCountMismatch}
	if !errors.Is(ref, ErrCounterCount) || errors.Is(ref, ErrCounterGeneration) {
		t.Fatal("count_mismatch unwraps wrong")
	}
	ref.Result = CounterStaleGeneration
	if !errors.Is(ref, ErrCounterGeneration) {
		t.Fatal("stale_generation unwraps wrong")
	}
}
