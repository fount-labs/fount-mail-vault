package vault

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/fount-labs/fount-mail-vault/internal/recovery"
	"github.com/fount-labs/fount-mail-vault/wire"
)

// OperatorBeginRequest carries the operator's own nonce, so the vault's document
// is fresh for this exchange.
type OperatorBeginRequest struct {
	AnswerNonce string `json:"answer_nonce"`
}

// OperatorBeginResponse is what vaultctl verifies before it seals anything: the
// document binds VaultKey to a release.
type OperatorBeginResponse struct {
	Nonce    string `json:"nonce"`
	Document []byte `json:"document"`
	VaultKey []byte `json:"vault_key"`
}

// SealedRequest is a share or an import, sealed from an ephemeral key.
type SealedRequest struct {
	Nonce       string `json:"nonce"`
	AnswerNonce string `json:"answer_nonce"`
	SenderKey   []byte `json:"sender_key"`
	Sealed      []byte `json:"sealed"`
}

// ImportRequest adds the operator's signature over the whole sealed request.
type ImportRequest struct {
	SealedRequest
	Signature []byte `json:"signature"`
}

// ImportMessage is what the operator signs. It covers both nonces, so a captured
// request can't be replayed, and the box, so it can't be swapped.
func ImportMessage(r SealedRequest) []byte {
	msg := []byte("fount-mail-vault/import/v1\x00")
	for _, part := range []string{r.Nonce, r.AnswerNonce} {
		msg = append(msg, part...)
		msg = append(msg, 0)
	}
	msg = append(msg, r.SenderKey...)
	return append(msg, r.Sealed...)
}

func (s *Server) handleOperatorBegin(w http.ResponseWriter, r *http.Request) {
	var req OperatorBeginRequest
	if !decode(w, r, 1<<12, &req) {
		return
	}
	answer, err := wire.DecodeNonce(req.AnswerNonce)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	nonce, err := s.issueNonce(useOperator)
	if err != nil {
		writeError(w, http.StatusTooManyRequests, err)
		return
	}
	doc, err := s.attester.Attest(r.Context(), answer)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, OperatorBeginResponse{Nonce: nonce, Document: doc, VaultKey: s.transfer.PublicKey().Bytes()})
}

// openSealed consumes the nonce and opens the box. The caller has already decided
// whether it trusts the sender.
func (s *Server) openSealed(w http.ResponseWriter, req SealedRequest, p wire.Purpose) ([]byte, bool) {
	issued, err := wire.DecodeNonce(req.Nonce)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return nil, false
	}
	answer, err := wire.DecodeNonce(req.AnswerNonce)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return nil, false
	}
	sender, err := wire.ParseRawKey(req.SenderKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return nil, false
	}
	expires, err := s.checkNonce(req.Nonce, useOperator)
	if err != nil {
		s.refuse(w, "nonce", err)
		return nil, false
	}
	plaintext, err := wire.Open(p, s.transfer, sender, wire.Nonces{Issued: issued, Answer: answer}, req.Sealed)
	if err != nil {
		s.refuse(w, "open", err)
		return nil, false
	}
	class := spentShare
	if p == wire.PurposeImport {
		class = spentImport
	}
	if err := s.spend(req.Nonce, expires, class); err != nil {
		clear(plaintext)
		s.refuse(w, "nonce", err)
		return nil, false
	}
	return plaintext, true
}

// handleShare collects shares into an empty vault, and installs the keyset once
// some of them rebuild the committed one. A share must be sealed from the key of
// the recipient whose index it carries, so only a shareholder can fill a slot,
// and there is one slot per recipient: a later share from the same recipient
// replaces the earlier one (vault re-review N3). Anyone else is refused before
// their nonce is spent.
func (s *Server) handleShare(w http.ResponseWriter, r *http.Request) {
	var req SealedRequest
	if !decode(w, r, 1<<16, &req) {
		return
	}
	if s.cfg.Commitment == "" {
		writeError(w, http.StatusConflict, errors.New("this release has no commitment to restore against"))
		return
	}
	if s.holds() {
		writeError(w, http.StatusConflict, errHeld)
		return
	}
	slot := s.recipientSlot(req.SenderKey)
	if slot == 0 {
		writeError(w, http.StatusForbidden, errors.New("refused at sender: a share must be sealed from a RECOVERY_RECIPIENTS identity"))
		return
	}
	// The recipient keys are public, so only a box that opens, which only the
	// identity could have sealed, counts against the recipient's budget.
	if !s.shareTurn(slot, time.Now(), false) {
		writeError(w, http.StatusTooManyRequests, fmt.Errorf("recipient %d has sent %d shares in %s; wait", slot, maxSharesPerRecipient, nonceLifetime))
		return
	}
	share, ok := s.openSealed(w, req, wire.PurposeShare)
	if !ok {
		return
	}
	s.shareTurn(slot, time.Now(), true)
	if len(share) < 2 || int(share[0]) != slot {
		label := share0(share)
		clear(share)
		s.refuse(w, "share", fmt.Errorf("recipient %d sent a share labelled %d", slot, label))
		return
	}
	s.mu.Lock()
	if s.pending == nil {
		s.pending = make(map[int][]byte)
	}
	clear(s.pending[slot])
	s.pending[slot] = share
	pending := make([][]byte, 0, len(s.pending))
	for _, p := range s.pending {
		pending = append(pending, p)
	}
	s.mu.Unlock()

	k, err := recovery.Combine(pending, s.cfg.Threshold, s.cfg.Commitment)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "restored": false, "pending_shares": len(pending)})
		return
	}
	s.install(k, nil, nil, "restored from recovery shares")
	s.mu.Lock()
	for _, p := range s.pending {
		clear(p)
	}
	s.pending = nil
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "restored": true, "commitment": k.Commitment()})
}

// recipientSlot is the share index the sender may fill: one more than its place
// in RECOVERY_RECIPIENTS, or 0 if it isn't a recipient.
func (s *Server) recipientSlot(sender []byte) int {
	for i, k := range s.cfg.RecipientKeys {
		if subtle.ConstantTimeCompare(k.Bytes(), sender) == 1 {
			return i + 1
		}
	}
	return 0
}

// shareTurn reports whether the recipient is within its budget, and with take
// counts a submission against it. The budget keeps one recipient, even with a
// stolen identity, from filling spentShare for the rest.
func (s *Server) shareTurn(slot int, now time.Time, take bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shareTimes == nil {
		s.shareTimes = make(map[int][]time.Time)
	}
	recent := s.shareTimes[slot][:0]
	for _, t := range s.shareTimes[slot] {
		if now.Sub(t) < nonceLifetime {
			recent = append(recent, t)
		}
	}
	if take {
		recent = append(recent, now)
	}
	s.shareTimes[slot] = recent
	return take || len(recent) < maxSharesPerRecipient
}

func share0(share []byte) int {
	if len(share) == 0 {
		return 0
	}
	return int(share[0])
}

// handleImport replaces the S3 credentials. AWS issues them, so they're the one
// secret the vault can't generate, and the operator's signature is what stops
// anyone else from overwriting them.
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	var req ImportRequest
	if !decode(w, r, 1<<16, &req) {
		return
	}
	if !ed25519.Verify(s.cfg.OperatorKey, ImportMessage(req.SealedRequest), req.Signature) {
		s.refuse(w, "signature", errors.New("not signed by OPERATOR_KEY"))
		return
	}
	plaintext, ok := s.openSealed(w, req.SealedRequest, wire.PurposeImport)
	if !ok {
		return
	}
	var creds wire.S3Credentials
	err := json.Unmarshal(plaintext, &creds)
	clear(plaintext)
	if err != nil || creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		writeError(w, http.StatusBadRequest, errors.New("import must carry both S3 credentials"))
		return
	}
	s.mu.Lock()
	s.s3 = &creds
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"imported": true})
}
