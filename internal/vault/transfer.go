package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/mod/semver"

	"github.com/fount-labs/fount-mail-vault/internal/attest"
	"github.com/fount-labs/fount-mail-vault/wire"
)

func (s *Server) handleBegin(w http.ResponseWriter, _ *http.Request) {
	if !s.holds() {
		writeError(w, http.StatusConflict, errNoKeyset)
		return
	}
	nonce, err := s.issueNonce(useTransfer)
	if err != nil {
		writeError(w, http.StatusTooManyRequests, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.BeginResponse{Nonce: nonce, HolderKey: s.transfer.PublicKey().Bytes()})
}

// handleFinish is the only way the keyset leaves a vault. The channel is
// untrusted: TLS ends at the peer's shim and proves nothing about its code.
func (s *Server) handleFinish(w http.ResponseWriter, r *http.Request) {
	var req wire.FinishRequest
	if !decode(w, r, wire.MaxBodyBytes, &req) {
		return
	}
	issued, err := wire.DecodeNonce(req.Nonce)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	answer, err := wire.DecodeNonce(req.AnswerNonce)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// A Cloud coordinator booting a generation attests to its per-boot key
	// along with the nonce, so the document vouches for the key.
	attested := issued
	var coordinatorKey ed25519.PublicKey
	if len(req.CoordinatorKey) > 0 {
		if len(req.CoordinatorKey) != ed25519.PublicKeySize {
			writeError(w, http.StatusBadRequest, errors.New("coordinator_key is a 32-byte Ed25519 key"))
			return
		}
		coordinatorKey = req.CoordinatorKey
		attested = wire.BootNonce(issued, coordinatorKey)
	}
	expires, err := s.checkNonce(req.Nonce, useTransfer)
	if err != nil {
		s.refuse(w, "nonce", err)
		return
	}
	kind, peer, err := s.identify(req.Document, attested)
	if err != nil {
		s.refuse(w, "verify", err)
		return
	}
	s.recordPeer(kind, peer)
	if err := s.checkFloor(r.Context(), kind, peer); err != nil {
		s.refuse(w, "minimum tag", err)
		return
	}
	if kind == kindEdge && s.cfg.Commitment == "" {
		s.refuse(w, "commitment", errors.New("this release has no commitment, so it serves only vaults"))
		return
	}
	if coordinatorKey != nil && (kind != kindEdge || !s.cfg.CoordinatorMode) {
		s.refuse(w, "boot", errors.New("only a Cloud vault boots a generation, and only for a coordinator"))
		return
	}
	nonces := wire.Nonces{Issued: issued, Answer: answer}
	// The document says which transfer key is attested, not that the sender
	// holds it: anyone can fetch a genuine coordinator's document for a nonce
	// of their choosing. Nothing moves the register until the proof shows
	// the sender holds that key.
	class := spentPull
	if coordinatorKey != nil {
		if err := wire.VerifyBootProof(s.transfer, peer.Key, nonces, coordinatorKey, req.BootProof); err != nil {
			s.refuse(w, "boot proof", err)
			return
		}
		if err := s.checkCoordinatorHost(r.Context(), peer); err != nil {
			s.refuse(w, "coordinator host", err)
			return
		}
		class = spentBoot
	}
	if err := s.spend(req.Nonce, expires, class); err != nil {
		s.refuse(w, "nonce", err)
		return
	}

	s.mu.Lock()
	keyset, s3, send := s.keyset, s.s3, s.sendKeyset
	gen := s.genKeyset
	s.mu.Unlock()
	if keyset == nil {
		writeError(w, http.StatusConflict, errNoKeyset)
		return
	}
	p := wire.Payload{Keyset: keyset.MarshalBinary(), S3: s3}
	// The generation keyset and the register go to vaults only: a
	// coordinator that held the authority could certify itself.
	if kind == kindVault && gen != nil {
		history, err := json.Marshal(s.reg.snapshot())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		p.GenerationKeyset, p.Register = gen.MarshalBinary(), history
	}
	if coordinatorKey != nil {
		if err := s.takeBoot(); err != nil {
			log.Printf("boot for %s %s (%s): %v", peer.Repo, peer.Tag, peer.KeyFingerprint, err)
			writeError(w, http.StatusTooManyRequests, fmt.Errorf("refused at boot rate: %w", err))
			return
		}
		cert, n, err := s.boot(r.Context(), coordinatorKey)
		if err != nil {
			if errors.Is(err, errNothingMoved) {
				s.refundBoot()
			}
			log.Printf("boot for %s %s: %v", peer.Repo, peer.Tag, err)
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("booting a generation: %w", err))
			return
		}
		s.recordBoot(peer, n)
		p.GenerationCertificate = cert
		log.Printf("coordinator %s %s (%s) booted generation %d", peer.Repo, peer.Tag, peer.KeyFingerprint, n)
	}
	var sendSealed []byte
	// An edge can't authenticate a send keyset its release doesn't commit to, so
	// until this release has the send commitment, only vaults get it. An edge
	// whose document endorses a send-transfer key gets it in a box of its own,
	// sealed to that key, so the container holding `transfer` never sees it.
	if send != nil && (kind == kindVault || s.cfg.SendCommitment != "") {
		raw := send.MarshalBinary()
		if kind == kindEdge && peer.SendKey != nil {
			sendSealed, err = wire.Seal(wire.PurposeSendKeyset, s.transfer, peer.SendKey, nonces, raw)
			clear(raw)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		} else {
			p.SendKeyset = raw
		}
	}
	payload, err := json.Marshal(p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	sealed, err := wire.Seal(wire.PurposeKeyset, s.transfer, peer.Key, nonces, payload)
	clear(payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	doc, err := s.attester.Attest(r.Context(), answer)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.FinishResponse{Document: doc, HolderKey: s.transfer.PublicKey().Bytes(), Sealed: sealed, SendSealed: sendSealed})
}

// identify accepts a vault release or an edge release, and nothing else.
func (s *Server) identify(doc, nonce []byte) (peerKind, *attest.Peer, error) {
	vaultPeer, vaultErr := s.verifier.Verify(doc, nonce, s.cfg.vaultPin())
	if vaultErr == nil {
		return kindVault, vaultPeer, nil
	}
	edgePeer, edgeErr := s.verifier.Verify(doc, nonce, s.cfg.edgePin())
	if edgeErr == nil {
		return kindEdge, edgePeer, nil
	}
	return "", nil, fmt.Errorf("not a %s release (%v), and not a %s release (%v)", s.cfg.VaultRepo, vaultErr, s.cfg.EdgeRepo, edgeErr)
}

// checkFloor keeps keys away from releases older than the floor, which the pins
// alone allow. Vaults compare with this vault's own tag, and edges with
// EDGE_MIN_TAG, because the two repos' tags don't order each other.
func (s *Server) checkFloor(ctx context.Context, kind peerKind, peer *attest.Peer) error {
	if !validTag(peer.Tag) {
		return fmt.Errorf("peer release tag %q isn't a version", peer.Tag)
	}
	floor := s.cfg.EdgeMinTag
	if kind == kindVault {
		own, err := s.ownTag(ctx)
		if err != nil {
			return err
		}
		floor = own
	}
	if semver.Compare(peer.Tag, floor) < 0 {
		return fmt.Errorf("%s release %s is older than %s", kind, peer.Tag, floor)
	}
	return nil
}

func validTag(tag string) bool { return semver.IsValid(tag) }
