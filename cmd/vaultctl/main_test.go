package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fount-labs/fount-mail-vault/internal/recovery"
	"github.com/fount-labs/fount-mail-vault/wire"
)

func TestRecoveryKeygenOpensItsShare(t *testing.T) {
	dir := t.TempDir()
	var recipients, paths []string
	for _, name := range []string{"a.txt", "b.txt"} {
		path := filepath.Join(dir, name)
		if err := recoveryKeygen(path); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		_, rest, _ := strings.Cut(string(raw), "# public key: ")
		recipient, _, _ := strings.Cut(rest, "\n")
		recipients = append(recipients, recipient)
		if got, err := recoveryRecipient([]string{path}); err != nil || got != recipient {
			t.Fatalf("recovery-recipient = %q, %v; want %q", got, err, recipient)
		}
		paths = append(paths, path)
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v", name, info.Mode().Perm())
		}
	}
	if _, err := recovery.ParseRecipients(strings.Join(recipients, ",")); err != nil {
		t.Fatalf("printed recipients don't parse: %v", err)
	}
	k, err := wire.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := recovery.NewBundle(k, recipients, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		ids, err := readIdentities([]string{path})
		if err != nil {
			t.Fatal(err)
		}
		shares, err := b.Decrypt(ids)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		got, err := recovery.Combine(shares, 1, k.Commitment())
		if err != nil || got.Commitment() != k.Commitment() {
			t.Fatalf("%s doesn't restore the keyset: %v", path, err)
		}
	}
	if err := recoveryKeygen(paths[0]); err == nil {
		t.Fatal("overwrote an existing identity")
	}
}
