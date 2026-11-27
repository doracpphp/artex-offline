package knowledge

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Signing-key trust (docs §4.1). A pack's manifest.sig must verify against a
// trusted ed25519 public key, and the manifest's key_id must name that key.
//
// The recommended home for a key is the binary (embeddedKeys), so an attacker
// with only config write access cannot replace it. The environment may ADD a key
// (for trusting a key before one is embedded, and for tests), but never replace
// an embedded one: an env key under an embedded key's id is a configuration
// error. On top of that, the first import of a pack id pins the signing key's
// fingerprint (store.go): a later pack of the same id signed by any other key —
// for instance one an attacker added through the environment — is refused until
// the operator explicitly re-pins.
//
// embeddedKeys maps key_id -> base64-encoded ed25519 public key. It is empty
// until a real key is generated (cmd/artex-knowledge keygen) and pasted here,
// which is a deliberate, reviewed change. With no embedded key and no env key,
// import refuses every pack: a pack is only as trustworthy as the key that
// verifies it, and there is none.
var embeddedKeys = map[string]string{
	// "artex-knowledge-1": "<base64 ed25519 public key>",
}

const (
	// PubKeyEnv adds a base64 ed25519 public key to the embedded set, trusted
	// under KeyIDEnv (default "env").
	PubKeyEnv = "ARTEX_KNOWLEDGE_PUBKEY"
	// KeyIDEnv is the key_id the PubKeyEnv key answers to. It must not be the id
	// of an embedded key.
	KeyIDEnv = "ARTEX_KNOWLEDGE_KEY_ID"
	// defaultEnvKeyID is the key_id assumed when PubKeyEnv is set without KeyIDEnv.
	defaultEnvKeyID = "env"
)

// TrustedKey is one trusted signing key, as the pack list shows it.
type TrustedKey struct {
	KeyID       string `json:"key_id"`
	Fingerprint string `json:"fingerprint"` // KeyFingerprint (hex SHA-256 of the public key)
	Source      string `json:"source"`      // "embedded" | "env"
}

// TrustedKeys returns the ed25519 public keys this binary verifies packs
// against, by key_id: the embedded set plus, when PubKeyEnv is set, the env key
// under KeyIDEnv. An invalid env key, or one that reuses an embedded key's id,
// is an error rather than silently ignored, so a misconfiguration is visible
// instead of quietly changing which key a pack is checked against.
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
		if !ValidID(id) {
			return nil, fmt.Errorf("%s %q is invalid (1-64 characters from A-Z a-z 0-9 . _ + -)", KeyIDEnv, id)
		}
		if _, embedded := out[id]; embedded {
			return nil, fmt.Errorf("%s %q is the id of a key embedded in this binary; the environment may only add a key under a new id, not replace an embedded one", KeyIDEnv, id)
		}
		out[id] = pub
	}
	return out, nil
}

// TrustedKeyList describes the trusted keys for the operator (GET
// /api/knowledge/packs), so a fingerprint can be compared out of band.
func TrustedKeyList() ([]TrustedKey, error) {
	keys, err := TrustedKeys()
	if err != nil {
		return nil, err
	}
	out := make([]TrustedKey, 0, len(keys))
	for id, pub := range keys {
		src := "env"
		if _, ok := embeddedKeys[id]; ok {
			src = "embedded"
		}
		out = append(out, TrustedKey{KeyID: id, Fingerprint: KeyFingerprint(pub), Source: src})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyID < out[j].KeyID })
	return out, nil
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
