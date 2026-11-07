// Package opclient is the operator's side of the vault: fetching the recovery
// bundle, submitting a share, and importing S3 credentials. vaultctl wraps it.
package opclient

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/fount-labs/fount-mail-vault/internal/recovery"
	"github.com/fount-labs/fount-mail-vault/internal/vault"
	"github.com/fount-labs/fount-mail-vault/wire"
)

// VerifyVault checks the vault's document for the operator's nonce and returns
// its attested key. vaultctl pins the release tag the operator expects.
type VerifyVault func(doc, nonce []byte) (*ecdh.PublicKey, error)

type Client struct {
	HTTP   *http.Client
	Base   string // e.g. https://vault-a.example
	Verify VerifyVault
}

func (c *Client) Bundle(ctx context.Context) (*recovery.Bundle, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+"/recovery/bundle", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault answered %d: %.400s", resp.StatusCode, raw)
	}
	var b recovery.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// SubmitShare sends one decrypted share, sealed to the verified vault. It reports
// whether the vault has now restored.
func (c *Client) SubmitShare(ctx context.Context, share []byte) (restored bool, err error) {
	req, err := c.seal(ctx, wire.PurposeShare, share)
	if err != nil {
		return false, err
	}
	var out struct {
		Restored bool `json:"restored"`
	}
	if err := wire.PostJSON(ctx, c.HTTP, c.Base+"/recovery/share", req, &out); err != nil {
		return false, err
	}
	return out.Restored, nil
}

// ImportS3 replaces the vault's S3 credentials, signed with the operator key.
func (c *Client) ImportS3(ctx context.Context, creds wire.S3Credentials, operator ed25519.PrivateKey) error {
	plaintext, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	sealed, err := c.seal(ctx, wire.PurposeImport, plaintext)
	clear(plaintext)
	if err != nil {
		return err
	}
	req := vault.ImportRequest{SealedRequest: *sealed, Signature: ed25519.Sign(operator, vault.ImportMessage(*sealed))}
	var out map[string]bool
	return wire.PostJSON(ctx, c.HTTP, c.Base+"/operator/import", req, &out)
}

// seal verifies the vault first, so nothing is sealed to a key no release endorses.
func (c *Client) seal(ctx context.Context, p wire.Purpose, plaintext []byte) (*vault.SealedRequest, error) {
	if c.Verify == nil {
		return nil, errors.New("no vault verifier")
	}
	answer, err := wire.RandomNonce()
	if err != nil {
		return nil, err
	}
	var begun vault.OperatorBeginResponse
	if err := wire.PostJSON(ctx, c.HTTP, c.Base+"/operator/begin", vault.OperatorBeginRequest{AnswerNonce: hex.EncodeToString(answer)}, &begun); err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	attested, err := c.Verify(begun.Document, answer)
	if err != nil {
		return nil, fmt.Errorf("verifying vault: %w", err)
	}
	claimed, err := wire.ParseRawKey(begun.VaultKey)
	if err != nil || !claimed.Equal(attested) {
		return nil, errors.New("verifying vault: its key isn't the one its document endorses")
	}
	issued, err := wire.DecodeNonce(begun.Nonce)
	if err != nil {
		return nil, err
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sealed, err := wire.Seal(p, ephemeral, attested, wire.Nonces{Issued: issued, Answer: answer}, plaintext)
	if err != nil {
		return nil, err
	}
	return &vault.SealedRequest{
		Nonce:       begun.Nonce,
		AnswerNonce: hex.EncodeToString(answer),
		SenderKey:   ephemeral.PublicKey().Bytes(),
		Sealed:      sealed,
	}, nil
}
