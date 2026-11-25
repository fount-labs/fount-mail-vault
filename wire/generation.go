package wire

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// The generation keyset is the Cloud vault's third secret
// (docs/COORDINATOR-COUNTER.md): one Ed25519 seed, the authority that signs
// coordinator generation certificates and the counter's answers. It moves
// only from vault to vault. A coordinator never gets it, because a
// coordinator that held it could certify its own next generation.
//
// Its commitment is its public key, base64 as the mail edge reads
// COORDINATOR_AUTHORITY_KEY, so the vault's GENERATION_AUTHORITY_KEY, the
// edge's COORDINATOR_AUTHORITY_KEY and the coordinator's
// --coordinator-authority-key are one string.

const generationKeysetVersion = 1

// GenerationKeysetSize is MarshalBinary's length: a version byte and the seed.
const GenerationKeysetSize = 1 + ed25519.SeedSize

// GenerationKeyset is the authority's seed.
type GenerationKeyset struct {
	Seed [ed25519.SeedSize]byte
}

// GenerateGenerationKeyset draws a new authority.
func GenerateGenerationKeyset() (*GenerationKeyset, error) {
	k := &GenerationKeyset{}
	if _, err := rand.Read(k.Seed[:]); err != nil {
		return nil, err
	}
	return k, nil
}

// MarshalBinary is version 1, then the 32-byte seed.
func (k *GenerationKeyset) MarshalBinary() []byte {
	out := make([]byte, 0, GenerationKeysetSize)
	out = append(out, generationKeysetVersion)
	return append(out, k.Seed[:]...)
}

// ParseGenerationKeyset reads MarshalBinary's output.
func ParseGenerationKeyset(raw []byte) (*GenerationKeyset, error) {
	if len(raw) != GenerationKeysetSize || raw[0] != generationKeysetVersion {
		return nil, fmt.Errorf("a generation keyset is version %d and %d bytes", generationKeysetVersion, GenerationKeysetSize)
	}
	k := &GenerationKeyset{}
	copy(k.Seed[:], raw[1:])
	return k, nil
}

// Authority is the signing key.
func (k *GenerationKeyset) Authority() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(k.Seed[:]) }

// Public is the authority's public key.
func (k *GenerationKeyset) Public() ed25519.PublicKey {
	return k.Authority().Public().(ed25519.PublicKey)
}

// AuthorityKey is the commitment: the public key, base64 with padding.
func (k *GenerationKeyset) AuthorityKey() string {
	return base64.StdEncoding.EncodeToString(k.Public())
}

// Matches compares with an authority key from a release's config.
func (k *GenerationKeyset) Matches(authorityKey string) bool {
	want, err := ParseAuthorityKey(authorityKey)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(k.Public(), want) == 1
}

// ParseAuthorityKey reads GENERATION_AUTHORITY_KEY or
// COORDINATOR_AUTHORITY_KEY: a raw Ed25519 public key, base64 with padding.
func ParseAuthorityKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("an authority key is a raw Ed25519 public key, base64 with padding")
	}
	return raw, nil
}

// GenerationCertificateLabel separates a certificate's signature from
// everything else the authority signs (mail edge internal/generation).
const GenerationCertificateLabel = "fount-coordinator-generation/v1\n"

// maxCertificate is the edge's limit on a certificate.
const maxCertificate = 1024

// GenerationCertificate is a certificate's payload, in the edge's format
// (DESIGN.md §8): {"generation", "coordinator_key" (base64), "issued_at"}.
type GenerationCertificate struct {
	Generation     uint64 `json:"generation"`
	CoordinatorKey []byte `json:"coordinator_key"`
	IssuedAt       int64  `json:"issued_at"`
}

func (c GenerationCertificate) check() error {
	if c.Generation == 0 || len(c.CoordinatorKey) != ed25519.PublicKeySize {
		return errors.New("a generation certificate names generation 1 or above and a 32-byte Ed25519 key")
	}
	return nil
}

// SignGenerationCertificate is b64url(json) "." b64url(Ed25519 over the label
// and the json).
func SignGenerationCertificate(authority ed25519.PrivateKey, c GenerationCertificate) (string, error) {
	if err := c.check(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(authority, append([]byte(GenerationCertificateLabel), payload...))
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(sig), nil
}

// VerifyGenerationCertificate checks a certificate as the edge does.
func VerifyGenerationCertificate(cert string, authority ed25519.PublicKey) (GenerationCertificate, error) {
	var c GenerationCertificate
	if len(authority) != ed25519.PublicKeySize {
		return c, errors.New("generation certificate: no authority key")
	}
	if len(cert) > maxCertificate {
		return c, errors.New("generation certificate: too long")
	}
	p, s, ok := strings.Cut(cert, ".")
	if !ok {
		return c, errors.New("generation certificate: malformed")
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(p)
	if err != nil {
		return c, fmt.Errorf("generation certificate: payload: %w", err)
	}
	sig, err := enc.DecodeString(s)
	if err != nil {
		return c, fmt.Errorf("generation certificate: signature: %w", err)
	}
	if !ed25519.Verify(authority, append([]byte(GenerationCertificateLabel), payload...), sig) {
		return c, errors.New("generation certificate: the signature doesn't verify")
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, fmt.Errorf("generation certificate: %w", err)
	}
	return c, c.check()
}

// bootLabel separates the boot nonce from every other use of a hash.
const bootLabel = "fount-coordinator-boot/v1\x00"

// BootNonce is what a coordinator attests to when its pull boots a
// generation: the holder's one-use nonce bound to the coordinator's
// per-boot key, so the document vouches for that key and nobody in the
// middle can swap it.
func BootNonce(issued []byte, coordinatorKey ed25519.PublicKey) []byte {
	h := sha256.New()
	h.Write([]byte(bootLabel))
	h.Write(issued)
	h.Write(coordinatorKey)
	return h.Sum(nil)
}

// bootProofInfo separates the boot proof's key from the boxes' keys, which
// come from the same X25519 agreement.
const bootProofInfo = "fount-mail-vault/v1/boot-proof\x00"

// BootProof shows that a boot's requester holds the private half of the
// transfer key its document endorses. A document alone proves nothing about
// the sender: the enclave's shim serves one for any nonce to anyone, so
// without the proof anyone could attest a genuine coordinator to their own
// per-boot key and take a generation (security review 2026-11-24, C1).
//
// It is an HMAC under a key from X25519(mine, peer), which only the two
// attested transfer keys can compute, over everything the boot binds: both
// transfer keys, both nonces and the per-boot key. The requester calls it
// with its transfer key and the holder's, from BeginResponse.HolderKey; the
// holder with its own and the requester's attested key. A holder key that
// isn't the holder's makes a proof the holder refuses, so HolderKey needs no
// authentication of its own.
func BootProof(mine *ecdh.PrivateKey, peer, requester, holder *ecdh.PublicKey, n Nonces, coordinatorKey ed25519.PublicKey) ([]byte, error) {
	if len(n.Issued) != NonceSize || len(n.Answer) != NonceSize {
		return nil, fmt.Errorf("nonces must be %d bytes", NonceSize)
	}
	if len(coordinatorKey) != ed25519.PublicKeySize {
		return nil, errors.New("a boot proof needs the coordinator's Ed25519 key")
	}
	shared, err := mine.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("key agreement: %w", err)
	}
	key, err := hkdf.Key(sha256.New, shared, nil, bootProofInfo, 32)
	clear(shared)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(bootLabel))
	m.Write(requester.Bytes())
	m.Write(holder.Bytes())
	m.Write(n.Issued)
	m.Write(n.Answer)
	m.Write(coordinatorKey)
	return m.Sum(nil), nil
}

// VerifyBootProof is the holder's side of BootProof: me is its transfer key,
// requester the key the requester's document endorses.
func VerifyBootProof(me *ecdh.PrivateKey, requester *ecdh.PublicKey, n Nonces, coordinatorKey ed25519.PublicKey, proof []byte) error {
	if len(proof) == 0 {
		return errors.New("a boot needs a boot proof: this coordinator release predates it")
	}
	want, err := BootProof(me, requester, requester, me.PublicKey(), n, coordinatorKey)
	if err != nil {
		return err
	}
	if !hmac.Equal(want, proof) {
		return errors.New("the boot proof doesn't verify: the requester doesn't hold the transfer key its document endorses")
	}
	return nil
}
