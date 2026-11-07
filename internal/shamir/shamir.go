// Package shamir splits a secret into n shares so that any k rebuild it and fewer
// reveal nothing. It works bytewise over GF(256) with the AES polynomial, and
// every operation on secret bytes is constant-time: no table lookups, no branches.
package shamir

import (
	"crypto/rand"
	"errors"
	"fmt"
)

const maxShares = 255

// Split returns n shares. Each is one byte of x, from 1 to n, then one byte of y
// per secret byte.
func Split(secret []byte, n, k int) ([][]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret is empty")
	}
	if k < 1 || k > n || n > maxShares {
		return nil, fmt.Errorf("can't make %d shares with threshold %d", n, k)
	}
	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = make([]byte, 1+len(secret))
		shares[i][0] = byte(i + 1)
	}
	coeffs := make([]byte, k)
	for b, s := range secret {
		coeffs[0] = s
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, err
		}
		for i := range shares {
			shares[i][1+b] = evaluate(coeffs, shares[i][0])
		}
	}
	clear(coeffs)
	return shares, nil
}

// Combine rebuilds the secret from shares with distinct x. Given fewer than the
// threshold, or a wrong share, it returns a wrong secret, not an error, so callers
// must check the result against something, as the vault does with its commitment.
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares")
	}
	size := len(shares[0])
	if size < 2 {
		return nil, errors.New("share is too short")
	}
	seen := make(map[byte]bool, len(shares))
	for _, s := range shares {
		if len(s) != size {
			return nil, errors.New("shares differ in length")
		}
		if s[0] == 0 || seen[s[0]] {
			return nil, fmt.Errorf("share x=%d is zero or repeated", s[0])
		}
		seen[s[0]] = true
	}
	// Lagrange basis at zero. The x values are public, so these needn't be secret.
	basis := make([]byte, len(shares))
	for i, si := range shares {
		num, den := byte(1), byte(1)
		for j, sj := range shares {
			if i != j {
				num = mul(num, sj[0])
				den = mul(den, sj[0]^si[0])
			}
		}
		basis[i] = mul(num, inverse(den))
	}
	secret := make([]byte, size-1)
	for b := range secret {
		var v byte
		for i, s := range shares {
			v ^= mul(s[1+b], basis[i])
		}
		secret[b] = v
	}
	return secret, nil
}

// evaluate uses Horner's rule.
func evaluate(coeffs []byte, x byte) byte {
	var v byte
	for i := len(coeffs) - 1; i >= 0; i-- {
		v = mul(v, x) ^ coeffs[i]
	}
	return v
}

// mul multiplies in GF(256) modulo x^8 + x^4 + x^3 + x + 1, with masks instead of
// branches.
func mul(a, b byte) byte {
	var p byte
	for range 8 {
		p ^= a & -(b & 1)
		carry := -(a >> 7)
		a = a<<1 ^ 0x1b&carry
		b >>= 1
	}
	return p
}

// inverse is a^254, which is a^-1 for every nonzero a.
func inverse(a byte) byte {
	result := byte(1)
	for range 7 {
		a = mul(a, a)
		result = mul(result, a)
	}
	return result
}
