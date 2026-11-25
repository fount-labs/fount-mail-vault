package recovery

import (
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/fount-labs/fount-mail-vault/wire"
)

func TestIdentityKeyMatchesItsRecipient(t *testing.T) {
	for range 20 {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		k, err := IdentityKey(id)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := RecipientKey(id.Recipient().String())
		if err != nil {
			t.Fatal(err)
		}
		if !k.PublicKey().Equal(pub) {
			t.Fatal("identity key and recipient key differ")
		}
	}
}

func TestBech32RefusesDamage(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	r := id.Recipient().String()
	flipped := []byte(r)
	if flipped[10] == 'q' {
		flipped[10] = 'p'
	} else {
		flipped[10] = 'q'
	}
	for name, s := range map[string]string{
		"checksum":   string(flipped),
		"mixed case": "A" + r[1:],
		"no data":    "age1",
	} {
		if _, _, err := bech32Decode(s); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	if _, err := RecipientKey(strings.ToUpper(id.String())); err == nil {
		t.Error("an identity parsed as a recipient")
	}
}

func TestOpenSaysWhichIdentityOpenedEachShare(t *testing.T) {
	var ids []age.Identity
	var recipients []string
	for range 3 {
		id, _ := age.GenerateX25519Identity()
		ids = append(ids, id)
		recipients = append(recipients, id.Recipient().String())
	}
	b := mustBundle(t, recipients)
	opened, err := b.Open([]age.Identity{ids[2], ids[0]})
	if err != nil {
		t.Fatal(err)
	}
	if len(opened) != 2 {
		t.Fatalf("opened %d shares, want 2", len(opened))
	}
	for _, o := range opened {
		want, _ := RecipientKey(recipients[o.Index-1])
		if !o.Key.PublicKey().Equal(want) || int(o.Share[0]) != o.Index {
			t.Fatalf("share %d opened with the wrong key", o.Index)
		}
	}
}

func mustBundle(t *testing.T, recipients []string) *Bundle {
	t.Helper()
	k, err := wire.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBundle(k, recipients, 2)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
