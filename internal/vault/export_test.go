package vault

import "github.com/fount-labs/fount-mail-vault/wire"

// ForceKeyset installs a keyset with no checks, to build a holder that misbehaves.
func (s *Server) ForceKeyset(k *wire.Keyset) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyset = k
}
