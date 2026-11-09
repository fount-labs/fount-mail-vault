package vault

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"

	"github.com/fount-labs/fount-mail-vault/wire"
)

// SendPublic is the public half of a send keyset, in the forms DNS and the relay
// take: DKIM TXT values (RFC 6376 for RSA, RFC 8463 for Ed25519) and the relay's
// pin, the hex SHA-256 of the client key's SubjectPublicKeyInfo.
type SendPublic struct {
	DKIMRSATXT     string `json:"dkim_rsa_txt"`
	DKIMEd25519TXT string `json:"dkim_ed25519_txt"`
	RelayClientPin string `json:"relay_client_pin"`
}

func sendPublic(k *wire.SendKeyset) (*SendPublic, error) {
	rsaKey, err := k.DKIMRSA()
	if err != nil {
		return nil, err
	}
	rsaSPKI, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return nil, err
	}
	dkimEd, err := k.DKIMEd25519()
	if err != nil {
		return nil, err
	}
	relay, err := k.RelayClient()
	if err != nil {
		return nil, err
	}
	relaySPKI, err := x509.MarshalPKIXPublicKey(relay.Public())
	if err != nil {
		return nil, err
	}
	pin := sha256.Sum256(relaySPKI)
	return &SendPublic{
		DKIMRSATXT:     "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(rsaSPKI),
		DKIMEd25519TXT: "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(dkimEd.Public().(ed25519.PublicKey)),
		RelayClientPin: hex.EncodeToString(pin[:]),
	}, nil
}
