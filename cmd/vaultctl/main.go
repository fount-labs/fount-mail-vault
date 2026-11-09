// Command vaultctl is the operator's tool: it fetches and checks the recovery
// bundle, submits a share to an empty vault, and imports S3 credentials. Every
// command that sends something verifies the vault's attestation first.
package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/fount-labs/fount-mail-vault/internal/attest"
	"github.com/fount-labs/fount-mail-vault/internal/opclient"
	"github.com/fount-labs/fount-mail-vault/internal/recovery"
	"github.com/fount-labs/fount-mail-vault/wire"
)

const usage = `vaultctl <command> [flags]

  bundle          -vault HOST -out FILE
  check-bundle    -bundle FILE -identity FILE [-identity FILE ...]
  submit-share    -vault HOST -tag vX.Y.Z -bundle FILE -identity FILE [-offline-first]
                  (-offline-first decrypts with the network off, then waits for Enter before it connects)
  import-s3       -vault HOST -tag vX.Y.Z -operator-key FILE   (reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
  operator-keygen -out FILE
  recovery-keygen -out FILE   (an age identity for one shareholder; run it offline)
  recovery-recipient -identity FILE   (prints its age1… recipient, to check a copy)
`

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	host := fs.String("vault", "", "vault hostname")
	tag := fs.String("tag", "", "the vault release tag you expect")
	repo := fs.String("repo", "fount-labs/fount-mail-vault", "the vault repo")
	out := fs.String("out", "", "output file")
	bundlePath := fs.String("bundle", "", "recovery bundle")
	operatorKey := fs.String("operator-key", "", "operator key file")
	offlineFirst := fs.Bool("offline-first", false, "submit-share: decrypt first, then wait for Enter before any network call")
	var identities multi
	fs.Var(&identities, "identity", "age identity file")
	fs.Parse(os.Args[2:])

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	switch os.Args[1] {
	case "bundle":
		err = fetchBundle(ctx, client(*host, "", ""), *out)
	case "check-bundle":
		err = checkBundle(*bundlePath, identities)
	case "submit-share":
		var gate func(int) error
		if *offlineFirst {
			gate = func(opened int) error { return waitForEnter(os.Stdin, os.Stderr, opened) }
		}
		err = submitShare(context.Background(), client(*host, *repo, *tag), *bundlePath, identities, gate)
	case "import-s3":
		err = importS3(ctx, client(*host, *repo, *tag), *operatorKey)
	case "operator-keygen":
		err = operatorKeygen(*out)
	case "recovery-keygen":
		err = recoveryKeygen(*out)
	case "recovery-recipient":
		var r string
		if r, err = recoveryRecipient(identities); err == nil {
			fmt.Println("RECOVERY_RECIPIENT:", r)
		}
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vaultctl:", err)
		os.Exit(1)
	}
}

// client verifies against repo@tag. Pinning the tag means the operator states
// which release they're trusting, rather than any release the repo ever made.
func client(host, repo, tag string) *opclient.Client {
	if host == "" {
		fail("-vault is required")
	}
	c := &opclient.Client{HTTP: &http.Client{Timeout: 2 * time.Minute}, Base: "https://" + host}
	if repo == "" {
		return c
	}
	if tag == "" {
		fail("-tag is required: name the vault release you expect")
	}
	pin := repo + "@" + tag
	c.Verify = func(doc, nonce []byte) (*ecdh.PublicKey, error) {
		v, err := attest.NewVerifier()
		if err != nil {
			return nil, err
		}
		p, err := v.Verify(doc, nonce, pin)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "verified %s %s, transfer key %s\n", p.Repo, p.Tag, p.KeyFingerprint)
		return p.Key, nil
	}
	return c
}

func fetchBundle(ctx context.Context, c *opclient.Client, out string) error {
	if out == "" {
		return errors.New("-out is required")
	}
	b, err := c.Bundle(ctx)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, raw, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s: %d shares, threshold %d, commitment %s\n", out, len(b.Shares), b.Threshold, b.Commitment)
	fmt.Println("check it with check-bundle before relying on it")
	return nil
}

func readBundle(path string) (*recovery.Bundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b recovery.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &b, nil
}

func readIdentities(paths []string) ([]age.Identity, error) {
	if len(paths) == 0 {
		return nil, errors.New("-identity is required")
	}
	var ids []age.Identity
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		parsed, err := age.ParseIdentities(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		ids = append(ids, parsed...)
	}
	return ids, nil
}

// checkBundle rebuilds the keyset offline and compares it with the commitment. It
// needs at least the threshold of identities, and proves the bundle restores.
func checkBundle(path string, identityPaths []string) error {
	b, err := readBundle(path)
	if err != nil {
		return err
	}
	ids, err := readIdentities(identityPaths)
	if err != nil {
		return err
	}
	shares, err := b.Decrypt(ids)
	if err != nil {
		return err
	}
	k, err := recovery.Combine(shares, b.Threshold, b.Commitment)
	if err != nil {
		return fmt.Errorf("%d of %d needed shares opened: %w", len(shares), b.Threshold, err)
	}
	fmt.Printf("bundle restores the keyset with commitment %s\n", k.Commitment())
	return nil
}

// offlinePrompt is what -offline-first prints once the shares are open.
const offlinePrompt = "Eject the drive and turn the network on, then press Enter"

// submitShare opens every share it can before it touches the network. With a gate
// (-offline-first) it waits on it between the two, so the identity's drive is ejected
// before the laptop goes online. The timeout starts after the gate, since the vault's
// /operator/begin nonce lasts two minutes. Shares stay in memory and are zeroed.
func submitShare(parent context.Context, c *opclient.Client, path string, identityPaths []string, gate func(opened int) error) error {
	b, err := readBundle(path)
	if err != nil {
		return err
	}
	ids, err := readIdentities(identityPaths)
	if err != nil {
		return err
	}
	shares, err := b.Decrypt(ids)
	if err != nil {
		return err
	}
	defer func() {
		for _, share := range shares {
			clear(share)
		}
	}()
	if gate != nil {
		if err := gate(len(shares)); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	for _, share := range shares {
		restored, err := c.SubmitShare(ctx, share)
		clear(share)
		if err != nil {
			return err
		}
		if restored {
			fmt.Println("the vault restored the keyset")
			return nil
		}
	}
	fmt.Println("share accepted; the vault needs more before it can restore")
	return nil
}

// waitForEnter prints the prompt and blocks until a full line arrives on in. Anything
// short of a newline, such as EOF, aborts before the network is touched.
func waitForEnter(in io.Reader, out io.Writer, opened int) error {
	fmt.Fprintf(out, "opened %d share(s); nothing has been sent yet\n%s: ", opened, offlinePrompt)
	if _, err := bufio.NewReader(in).ReadString('\n'); err != nil {
		return fmt.Errorf("no Enter on stdin (%v); nothing was sent", err)
	}
	return nil
}

func importS3(ctx context.Context, c *opclient.Client, keyPath string) error {
	key, err := readOperatorKey(keyPath)
	if err != nil {
		return err
	}
	creds := wire.S3Credentials{AccessKeyID: os.Getenv("AWS_ACCESS_KEY_ID"), SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY")}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return errors.New("set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to the edge's S3 credentials")
	}
	if err := c.ImportS3(ctx, creds, key); err != nil {
		return err
	}
	fmt.Println("imported S3 credentials")
	return nil
}

func readOperatorKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("-operator-key is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s isn't a hex Ed25519 seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func operatorKeygen(out string) error {
	if out == "" {
		return errors.New("-out is required")
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, hex.EncodeToString(seed)); err != nil {
		return err
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	fmt.Printf("wrote %s\nOPERATOR_KEY: %s\n", out, hex.EncodeToString(pub))
	return nil
}

// recoveryKeygen writes an age identity in age-keygen's format, so the shareholder
// needs only this binary on the offline machine. It prints only the recipient.
func recoveryKeygen(out string) error {
	if out == "" {
		return errors.New("-out is required")
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	recipient := id.Recipient().String()
	_, err = fmt.Fprintf(f, "# created: %s\n# public key: %s\n%s\n", time.Now().UTC().Format(time.RFC3339), recipient, id)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s\nRECOVERY_RECIPIENT: %s\n", out, recipient)
	return nil
}

// recoveryRecipient prints the recipient an identity file opens, so a copy typed back
// in from paper can be checked against the one in the config.
func recoveryRecipient(paths []string) (string, error) {
	if len(paths) != 1 {
		return "", errors.New("give exactly one -identity")
	}
	ids, err := readIdentities(paths)
	if err != nil {
		return "", err
	}
	if len(ids) != 1 {
		return "", fmt.Errorf("%s holds %d identities, want 1", paths[0], len(ids))
	}
	x, ok := ids[0].(*age.X25519Identity)
	if !ok {
		return "", fmt.Errorf("%s isn't an X25519 identity", paths[0])
	}
	return x.Recipient().String(), nil
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "vaultctl:", msg)
	os.Exit(2)
}
