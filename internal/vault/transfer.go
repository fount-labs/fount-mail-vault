package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	writeJSON(w, http.StatusOK, wire.BeginResponse{Nonce: nonce})
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
	if err := s.consumeNonce(req.Nonce, useTransfer); err != nil {
		s.refuse(w, "nonce", err)
		return
	}
	kind, peer, err := s.identify(req.Document, issued)
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

	s.mu.Lock()
	keyset, s3, send := s.keyset, s.s3, s.sendKeyset
	s.mu.Unlock()
	if keyset == nil {
		writeError(w, http.StatusConflict, errNoKeyset)
		return
	}
	nonces := wire.Nonces{Issued: issued, Answer: answer}
	p := wire.Payload{Keyset: keyset.MarshalBinary(), S3: s3}
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
