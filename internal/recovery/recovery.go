// Package recovery makes and combines the shares that restore a keyset when every
// vault is gone. Each share is encrypted to one offline age identity.
package recovery

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"

	"github.com/fount-labs/fount-mail-vault/internal/shamir"
	"github.com/fount-labs/fount-mail-vault/wire"
)

const bundleVersion = 1

// Bundle reveals nothing without Threshold identities, so it can be stored anywhere.
type Bundle struct {
	Version    int     `json:"version"`
	Commitment string  `json:"commitment"`
	Threshold  int     `json:"threshold"`
	Shares     []Share `json:"shares"`
}

type Share struct {
	Index     int    `json:"index"`
	Recipient string `json:"recipient"`
	Encrypted []byte `json:"encrypted"`
}

// ParseRecipients reads a comma-separated list of age X25519 recipients.
func ParseRecipients(list string) ([]string, error) {
	var out []string
	seen := make(map[string]bool)
	for _, r := range strings.Split(list, ",") {
		if r = strings.TrimSpace(r); r == "" {
			continue
		}
		if _, err := age.ParseX25519Recipient(r); err != nil {
			return nil, fmt.Errorf("recipient %q: %w", r, err)
		}
		if seen[r] {
			return nil, fmt.Errorf("recipient %q is listed twice", r)
		}
		seen[r] = true
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, errors.New("no recovery recipients")
	}
	return out, nil
}

// NewBundle splits the keyset into one share per recipient.
func NewBundle(k *wire.Keyset, recipients []string, threshold int) (*Bundle, error) {
	shares, err := shamir.Split(k.MarshalBinary(), len(recipients), threshold)
	if err != nil {
		return nil, err
	}
	b := &Bundle{Version: bundleVersion, Commitment: k.Commitment(), Threshold: threshold}
	for i, r := range recipients {
		recipient, err := age.ParseX25519Recipient(r)
		if err != nil {
			return nil, err
		}
		var out bytes.Buffer
		w, err := age.Encrypt(&out, recipient)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(shares[i]); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		clear(shares[i])
		b.Shares = append(b.Shares, Share{Index: i + 1, Recipient: r, Encrypted: out.Bytes()})
	}
	return b, nil
}

// Decrypt opens whichever shares the identities can, on the shareholder's machine.
func (b *Bundle) Decrypt(identities []age.Identity) ([][]byte, error) {
	if b.Version != bundleVersion {
		return nil, fmt.Errorf("bundle version %d, want %d", b.Version, bundleVersion)
	}
	var out [][]byte
	for _, s := range b.Shares {
		r, err := age.Decrypt(bytes.NewReader(s.Encrypted), identities...)
		if err != nil {
			var noMatch *age.NoIdentityMatchError
			if errors.As(err, &noMatch) {
				continue
			}
			return nil, fmt.Errorf("share %d: %w", s.Index, err)
		}
		share, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("share %d: %w", s.Index, err)
		}
		if len(share) == 0 || int(share[0]) != s.Index {
			return nil, fmt.Errorf("share %d is labelled with another index", s.Index)
		}
		out = append(out, share)
	}
	if len(out) == 0 {
		return nil, errors.New("none of these identities opens a share in the bundle")
	}
	return out, nil
}

// Opened is a share with the identity that opened it, which the shareholder
// seals it from so the vault knows whose slot it fills.
type Opened struct {
	Index int
	Share []byte
	Key   *ecdh.PrivateKey
}

// Open is Decrypt for submitting: it tries each X25519 identity on its own, so
// it knows which one opened each share.
func (b *Bundle) Open(identities []age.Identity) ([]Opened, error) {
	if b.Version != bundleVersion {
		return nil, fmt.Errorf("bundle version %d, want %d", b.Version, bundleVersion)
	}
	var xs []*age.X25519Identity
	for _, id := range identities {
		if x, ok := id.(*age.X25519Identity); ok {
			xs = append(xs, x)
		}
	}
	var out []Opened
	for _, s := range b.Shares {
		for _, id := range xs {
			r, err := age.Decrypt(bytes.NewReader(s.Encrypted), id)
			if err != nil {
				var noMatch *age.NoIdentityMatchError
				if errors.As(err, &noMatch) {
					continue
				}
				return nil, fmt.Errorf("share %d: %w", s.Index, err)
			}
			share, err := io.ReadAll(r)
			if err != nil {
				return nil, fmt.Errorf("share %d: %w", s.Index, err)
			}
			if len(share) == 0 || int(share[0]) != s.Index {
				clear(share)
				return nil, fmt.Errorf("share %d is labelled with another index", s.Index)
			}
			key, err := IdentityKey(id)
			if err != nil {
				clear(share)
				return nil, fmt.Errorf("share %d: %w", s.Index, err)
			}
			out = append(out, Opened{Index: s.Index, Share: share, Key: key})
			break
		}
	}
	if len(out) == 0 {
		return nil, errors.New("none of these identities opens a share in the bundle")
	}
	return out, nil
}

// Combine looks for threshold shares that rebuild the committed keyset. It tries
// each set with distinct indexes, so a wrong share only costs time. The vault
// holds at most one share per recipient, which keeps that bounded.
func Combine(shares [][]byte, threshold int, commitment string) (*wire.Keyset, error) {
	if threshold < 1 || len(shares) < threshold {
		return nil, fmt.Errorf("have %d shares, need %d", len(shares), threshold)
	}
	var found *wire.Keyset
	var pick func(start int, chosen [][]byte, used map[byte]bool) bool
	pick = func(start int, chosen [][]byte, used map[byte]bool) bool {
		if len(chosen) == threshold {
			secret, err := shamir.Combine(chosen)
			if err != nil {
				return false
			}
			k, err := wire.ParseKeyset(secret)
			clear(secret)
			if err == nil && k.Matches(commitment) {
				found = k
				return true
			}
			return false
		}
		for i := start; i < len(shares); i++ {
			s := shares[i]
			if len(s) == 0 || used[s[0]] {
				continue
			}
			used[s[0]] = true
			if pick(i+1, append(chosen, s), used) {
				return true
			}
			delete(used, s[0])
		}
		return false
	}
	if pick(0, nil, map[byte]bool{}) {
		return found, nil
	}
	return nil, errors.New("no set of shares rebuilds the committed keyset")
}
