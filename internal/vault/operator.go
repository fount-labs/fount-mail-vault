package vault

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"

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
	if err := s.consumeNonce(req.Nonce, useOperator); err != nil {
		s.refuse(w, "nonce", err)
		return nil, false
	}
	plaintext, err := wire.Open(p, s.transfer, sender, wire.Nonces{Issued: issued, Answer: answer}, req.Sealed)
	if err != nil {
		s.refuse(w, "open", err)
		return nil, false
	}
	return plaintext, true
}

// handleShare collects shares into an empty vault, and installs the keyset once
// some of them rebuild the committed one. A share proves nothing about who sent
// it, so the commitment is the only check, and junk shares only cost a retry.
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
	share, ok := s.openSealed(w, req, wire.PurposeShare)
	if !ok {
		return
	}
	s.mu.Lock()
	if len(s.pending) >= maxPending {
		s.mu.Unlock()
		clear(share)
		writeError(w, http.StatusTooManyRequests, errors.New("too many shares held; redeploy the vault to clear them"))
		return
	}
	s.pending = append(s.pending, share)
	pending := append([][]byte(nil), s.pending...)
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
