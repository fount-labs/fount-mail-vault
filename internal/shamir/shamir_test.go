package shamir

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func secret(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// subsets calls f with every subset of shares of the given size.
func subsets(shares [][]byte, size int, f func([][]byte)) {
	var pick func(start int, chosen [][]byte)
	pick = func(start int, chosen [][]byte) {
		if len(chosen) == size {
			f(chosen)
			return
		}
		for i := start; i < len(shares); i++ {
			pick(i+1, append(chosen, shares[i]))
		}
	}
	pick(0, nil)
}

func TestEveryThresholdSubsetRebuilds(t *testing.T) {
	for _, c := range []struct{ n, k int }{{1, 1}, {2, 1}, {2, 2}, {3, 2}, {5, 3}, {6, 6}} {
		s := secret(t, 120)
		shares, err := Split(s, c.n, c.k)
		if err != nil {
			t.Fatal(err)
		}
		for size := c.k; size <= c.n; size++ {
			subsets(shares, size, func(chosen [][]byte) {
				got, err := Combine(chosen)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, s) {
					t.Errorf("%d of %d: %d shares didn't rebuild", c.k, c.n, size)
				}
			})
		}
	}
}

func TestBelowThresholdDoesNotRebuild(t *testing.T) {
	s := secret(t, 120)
	shares, err := Split(s, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	subsets(shares, 2, func(chosen [][]byte) {
		got, err := Combine(chosen)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(got, s) {
			t.Error("two shares of a 3-of-5 rebuilt the secret")
		}
	})
}

func TestOneShareOfTwoIsUniform(t *testing.T) {
	// With k=2, share y = s + a*x for random a. Over many splits of the same byte,
	// every y value should appear, or the share leaks the secret.
	seen := make(map[byte]bool)
	for range 4000 {
		shares, err := Split([]byte{0x42}, 2, 2)
		if err != nil {
			t.Fatal(err)
		}
		seen[shares[0][1]] = true
	}
	if len(seen) != 256 {
		t.Fatalf("one share took only %d of 256 values", len(seen))
	}
}

func TestFieldArithmetic(t *testing.T) {
	// Known AES-field products: 0x57 * 0x83 = 0xc1, and 0x57 * 0x13 = 0xfe.
	if mul(0x57, 0x83) != 0xc1 || mul(0x57, 0x13) != 0xfe {
		t.Fatal("multiplication disagrees with the AES field")
	}
	for a := 1; a < 256; a++ {
		if mul(byte(a), inverse(byte(a))) != 1 {
			t.Fatalf("inverse(%#x) is wrong", a)
		}
	}
}

func TestCombineRejectsBadShares(t *testing.T) {
	shares, err := Split(secret(t, 16), 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][][]byte{
		"none":     nil,
		"repeated": {shares[0], shares[0]},
		"lengths":  {shares[0], shares[1][:5]},
		"zero x":   {append([]byte{0}, shares[0][1:]...), shares[1]},
	} {
		if _, err := Combine(bad); err == nil {
			t.Errorf("%s: combined", name)
		}
	}
	if _, err := Split(nil, 2, 2); err == nil {
		t.Error("split an empty secret")
	}
	if _, err := Split([]byte{1}, 2, 3); err == nil {
		t.Error("split with threshold above n")
	}
}
