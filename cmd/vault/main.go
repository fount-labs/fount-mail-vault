// Command vault runs one Fount Mail vault enclave. It holds the keyset in memory
// only, and restores it from another vault after a restart.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/fount-labs/fount-mail-vault/internal/attest"
	"github.com/fount-labs/fount-mail-vault/internal/vault"
	"github.com/fount-labs/fount-mail-vault/wire"
)

const listenAddr = ":8080"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "health" {
		// The image is FROM scratch, so the binary is its own healthcheck.
		resp, err := http.Get("http://127.0.0.1" + listenAddr + "/health")
		if err != nil || resp.StatusCode != http.StatusOK {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
		return
	}
	cfg, err := vault.LoadConfig(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	transfer, err := wire.LoadTransferKey(wire.TransferKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := attest.NewVerifier()
	if err != nil {
		log.Fatal(err)
	}
	for _, pin := range []string{cfg.VaultRepo, cfg.EdgeRepo} {
		if err := verifier.CheckPin(pin); err != nil {
			log.Fatal(err)
		}
	}
	s := vault.NewServer(cfg, transfer, wire.NewSocketAttester(wire.AttestationSocket), verifier, &http.Client{Timeout: 90 * time.Second})
	go s.Run(context.Background())
	log.Printf("vault listening on %s, transfer key %s, commitment %q, peers %v", listenAddr, wire.Fingerprint(transfer.PublicKey()), cfg.Commitment, cfg.Peers)
	srv := &http.Server{Addr: listenAddr, Handler: s.Routes(), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
