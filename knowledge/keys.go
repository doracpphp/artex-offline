package knowledge

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// Signing-key trust (docs §4.1). A pack's manifest.sig is checked against the
// ed25519 public key whose id its manifest names. The recommended home for that
// key is the binary, so an attacker with config write access cannot swap it; an
// env override exists so a key can be trusted before one is baked in, and for
// tests.
//
// embeddedKeys maps key_id -> base64-encoded ed25519 public key. It is empty
// until a real key is generated (cmd/artex-knowledge keygen) and pasted here,
// which is a deliberate, reviewed change. With no embedded key and no override,
// import refuses every pack: a pack is only as trustworthy as the key that
// verifies it, and there is none.
var embeddedKeys = map[string]string{
	// "artex-knowledge-1": "<base64 ed25519 public key>",
}

const (
	// PubKeyEnv overrides/augments the embedded keys with a base64 ed25519 public
	// key, trusted under KeyIDEnv (default "env").
	PubKeyEnv = "ARTEX_KNOWLEDGE_PUBKEY"
	// KeyIDEnv is the key_id the PubKeyEnv key answers to.
	KeyIDEnv = "ARTEX_KNOWLEDGE_KEY_ID"
	// defaultEnvKeyID is the key_id assumed when PubKeyEnv is set without KeyIDEnv.
	defaultEnvKeyID = "env"
)

// TrustedKeys returns the ed25519 public keys this binary will verify packs
// against, by key_id: the embedded set plus, when PubKeyEnv is set, the override
// key under KeyIDEnv (which replaces an embedded key of the same id). An invalid
// override is an error rather than silently ignored, so a misconfigured key is
// visible instead of quietly disabling a pack.
func TrustedKeys() (map[string]ed25519.PublicKey, error) {
	out := make(map[string]ed25519.PublicKey)
	for id, b64 := range embeddedKeys {
		pub, err := parsePubKey(b64)
		if err != nil {
			return nil, fmt.Errorf("embedded knowledge key %q: %w", id, err)
		}
		out[id] = pub
	}
	if raw := strings.TrimSpace(os.Getenv(PubKeyEnv)); raw != "" {
		pub, err := parsePubKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", PubKeyEnv, err)
		}
		id := strings.TrimSpace(os.Getenv(KeyIDEnv))
		if id == "" {
			id = defaultEnvKeyID
		}
		out[id] = pub
	}
	return out, nil
}

// TrustedKey returns the public key for keyID among the trusted keys, or an
// error naming why it is not trusted — the two cases the importer must tell
// apart: no keys configured at all, versus a pack signed by an unknown key.
func TrustedKey(keyID string) (ed25519.PublicKey, error) {
	keys, err := TrustedKeys()
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no knowledge signing key is trusted: embed one in the binary or set %s (a pack is only trusted if a key can verify it)", PubKeyEnv)
	}
	pub, ok := keys[keyID]
	if !ok {
		return nil, fmt.Errorf("pack is signed by key_id %q, which is not trusted", keyID)
	}
	return pub, nil
}

func parsePubKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
