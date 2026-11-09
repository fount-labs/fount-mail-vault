package vault

import (
	"context"

	"github.com/fount-labs/fount-mail-vault/wire"
)

// ForceKeyset installs a keyset with no checks, to build a holder that misbehaves.
func (s *Server) ForceKeyset(k *wire.Keyset) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyset = k
}

// SelfCheck runs the self check Run would, which fills in the release and chip.
func (s *Server) SelfCheck(ctx context.Context) error { return s.selfCheck(ctx) }

// ForceSendKeyset installs a send keyset with no checks, to build a holder that misbehaves.
func (s *Server) ForceSendKeyset(k *wire.SendKeyset) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendKeyset = k
}

// RestoreFromPeers runs the restore loop once to completion or until ctx ends.
func (s *Server) RestoreFromPeers(ctx context.Context) { s.restoreLoop(ctx) }
