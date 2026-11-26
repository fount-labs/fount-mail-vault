package recovery

import (
	"crypto/ecdh"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"filippo.io/age"
)

// RecipientKey is the X25519 public key an age1… recipient names. The vault
// takes a share only when it's sealed from one of these keys, so a share
// proves which shareholder sent it.
func RecipientKey(r string) (*ecdh.PublicKey, error) {
	if _, err := age.ParseX25519Recipient(r); err != nil {
		return nil, err
	}
	hrp, data, err := bech32Decode(r)
	if err != nil {
		return nil, err
	}
	if hrp != "age" {
		return nil, fmt.Errorf("recipient has prefix %q, want age", hrp)
	}
	return ecdh.X25519().NewPublicKey(data)
}

// IdentityKey is the X25519 private key behind an age identity: the
// shareholder seals a share from it, and the vault opens it against the
// identity's recipient.
func IdentityKey(id *age.X25519Identity) (*ecdh.PrivateKey, error) {
	hrp, data, err := bech32Decode(id.String())
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if hrp != "age-secret-key-" {
		return nil, errors.New("not an age X25519 identity")
	}
	k, err := ecdh.X25519().NewPrivateKey(data)
	if err != nil {
		return nil, err
	}
	pub, err := RecipientKey(id.Recipient().String())
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(k.PublicKey().Bytes(), pub.Bytes()) != 1 {
		return nil, errors.New("identity's key doesn't match its recipient")
	}
	return k, nil
}

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// bech32Decode is BIP 173's decoding, as age uses it: no length limit, and the
// data converted from 5-bit groups to bytes.
func bech32Decode(s string) (string, []byte, error) {
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, errors.New("bech32 string mixes case")
	}
	s = strings.ToLower(s)
	sep := strings.LastIndexByte(s, '1')
	if sep < 1 || sep+7 > len(s) {
		return "", nil, errors.New("bech32 string has no separator or checksum")
	}
	hrp := s[:sep]
	for _, c := range hrp {
		if c < 33 || c > 126 {
			return "", nil, errors.New("bech32 prefix has an invalid character")
		}
	}
	values := make([]byte, 0, len(s)-sep-1)
	for _, c := range s[sep+1:] {
		v := strings.IndexRune(bech32Charset, c)
		if v < 0 {
			return "", nil, fmt.Errorf("bech32 data has invalid character %q", c)
		}
		values = append(values, byte(v))
	}
	if bech32Polymod(append(bech32HRPExpand(hrp), values...)) != 1 {
		return "", nil, errors.New("bech32 checksum doesn't match")
	}
	data, err := convertBits(values[:len(values)-6])
	clear(values)
	if err != nil {
		return "", nil, err
	}
	return hrp, data, nil
}

func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := range 5 {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, 2*len(hrp)+1)
	for i := range len(hrp) {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := range len(hrp) {
		out = append(out, hrp[i]&31)
	}
	return out
}

// convertBits regroups 5-bit values into bytes, refusing non-zero padding.
func convertBits(values []byte) ([]byte, error) {
	var acc uint32
	var bits uint
	out := make([]byte, 0, len(values)*5/8)
	for _, v := range values {
		acc = acc<<5 | uint32(v)
		bits += 5
		for bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	if bits >= 5 || (acc<<(8-bits))&0xff != 0 {
		return nil, errors.New("bech32 data has invalid padding")
	}
	return out, nil
}
