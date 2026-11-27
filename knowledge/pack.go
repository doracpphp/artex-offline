// Package knowledge implements ARTEX's offline knowledge packs: signed archives
// of penetration-testing reference data (ExploitDB, NVD, technique docs) built in
// an online environment and imported into an offline one, where they back the
// search_* / lookup_* agent tools (docs/offline-knowledge-search.md).
//
// A pack is a tar.gz with, at its root:
//
//	manifest.json  the pack id, version, sources, and the size + SHA-256 of every
//	               other file (see Manifest)
//	manifest.sig   an ed25519 signature over the exact bytes of manifest.json
//	<data files>   exploitdb/, nvd/, docs/, ... every one listed in the manifest
//
// The pack is a trust boundary (docs §7): on import the signature is checked
// first, then every file's hash as it is extracted, and nothing unlisted is
// written. This file defines the format and the signature; extract.go does the
// safe extraction, and the cmd/artex-knowledge builder writes packs.
package knowledge

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"
)

// ManifestName and SigName are the two fixed entries at a pack's root.
const (
	ManifestName = "manifest.json"
	SigName      = "manifest.sig"
)

// Manifest is the content of manifest.json. The signature covers the exact bytes
// of this file as written, so the importer verifies before it parses: see
// VerifyManifest.
type Manifest struct {
	// PackID is a stable identifier for the knowledge set (e.g. "artex-core").
	// Packs with the same id are versions of the same set; a downgrade is refused
	// unless the operator confirms it (store.go).
	PackID string `json:"pack_id"`
	// Version orders packs of one id. Any monotonic string works; the builder
	// uses the build date, e.g. "2026.11.27".
	Version string `json:"version"`
	// BaseVersion, when set, marks a delta pack that applies only on top of an
	// active pack of exactly that version (Phase 1 builds full packs only; the
	// field is defined so the format need not change later).
	BaseVersion string `json:"base_version,omitempty"`
	// BuiltAt is when the pack was generated, in UTC.
	BuiltAt time.Time `json:"built_at"`
	// KeyID names the signing key, so a key can be rotated by shipping a new
	// binary without invalidating packs signed with the previous one.
	KeyID string `json:"key_id"`
	// Sources records what went into the pack and under what license, for
	// provenance and redistribution checks.
	Sources []Source `json:"sources"`
	// Files lists every pack entry except manifest.json and manifest.sig, with
	// the size and SHA-256 the importer checks as it extracts.
	Files []FileEntry `json:"files"`
	// Deletions lists paths a delta pack removes from the base (unused by full
	// packs).
	Deletions []string `json:"deletions,omitempty"`
}

// Source is one upstream dataset a pack was built from.
type Source struct {
	Name    string `json:"name"`              // e.g. "exploitdb", "nvd"
	Version string `json:"version,omitempty"` // upstream tag / snapshot date
	License string `json:"license,omitempty"`
}

// FileEntry is one data file of a pack, as the manifest records it.
type FileEntry struct {
	Path   string `json:"path"`   // slash path within the pack, e.g. "exploitdb/files_exploits.csv"
	Size   int64  `json:"size"`   // exact byte length
	SHA256 string `json:"sha256"` // lower-case hex of the SHA-256
}

// Marshal returns the canonical JSON of a manifest: indented, with a trailing
// newline. The builder writes exactly these bytes as manifest.json and signs
// them, so the importer can verify the raw bytes before parsing (VerifyManifest).
func (m *Manifest) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ParseManifest decodes manifest bytes. It does not verify the signature; use
// VerifyManifest for the bytes and this for what they contain.
func ParseManifest(b []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// Validate checks a parsed manifest for internal consistency, independently of
// any signature: required fields, well-formed file entries, and no duplicate or
// unsafe paths. A valid manifest names only files that SafePath accepts.
func (m *Manifest) Validate() error {
	if strings.TrimSpace(m.PackID) == "" {
		return fmt.Errorf("manifest: pack_id is required")
	}
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("manifest: version is required")
	}
	if strings.TrimSpace(m.KeyID) == "" {
		return fmt.Errorf("manifest: key_id is required")
	}
	seen := make(map[string]bool, len(m.Files))
	for _, f := range m.Files {
		clean, err := SafePath(f.Path)
		if err != nil {
			return fmt.Errorf("manifest: file %q: %w", f.Path, err)
		}
		if clean == ManifestName || clean == SigName {
			return fmt.Errorf("manifest: file %q collides with a reserved name", f.Path)
		}
		if seen[clean] {
			return fmt.Errorf("manifest: duplicate file %q", clean)
		}
		seen[clean] = true
		if f.Size < 0 {
			return fmt.Errorf("manifest: file %q has a negative size", f.Path)
		}
		if len(f.SHA256) != 64 || !isHex(f.SHA256) {
			return fmt.Errorf("manifest: file %q has an invalid sha256 %q", f.Path, f.SHA256)
		}
	}
	for _, d := range m.Deletions {
		if _, err := SafePath(d); err != nil {
			return fmt.Errorf("manifest: deletion %q: %w", d, err)
		}
	}
	return nil
}

// fileByPath indexes the manifest's files by their cleaned path.
func (m *Manifest) fileByPath() map[string]FileEntry {
	out := make(map[string]FileEntry, len(m.Files))
	for _, f := range m.Files {
		if clean, err := SafePath(f.Path); err == nil {
			out[clean] = f
		}
	}
	return out
}

// TotalSize is the sum of the declared file sizes, for the disk-space and
// decompression-bomb checks in extract.go.
func (m *Manifest) TotalSize() int64 {
	var n int64
	for _, f := range m.Files {
		n += f.Size
	}
	return n
}

// SignManifest returns the ed25519 signature of manifestBytes. The builder signs
// the exact bytes it writes as manifest.json.
func SignManifest(priv ed25519.PrivateKey, manifestBytes []byte) []byte {
	return ed25519.Sign(priv, manifestBytes)
}

// VerifyManifest checks sig against manifestBytes with pub. It is called before
// the bytes are parsed, so a malformed or hostile manifest cannot act until its
// signature is confirmed.
func VerifyManifest(pub ed25519.PublicKey, manifestBytes, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("verify: public key is not %d bytes", ed25519.PublicKeySize)
	}
	if !ed25519.Verify(pub, manifestBytes, sig) {
		return fmt.Errorf("verify: manifest signature does not match the trusted key")
	}
	return nil
}

// SafePath cleans a slash-separated pack path and rejects anything that could
// escape the extraction directory: absolute paths, "..", a leading or doubled
// slash, an empty component, or a Windows volume/backslash. It returns the clean
// forward-slash path, which is also the key used to match manifest and archive
// entries.
func SafePath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("NUL in path")
	}
	// Reject Windows drive letters and backslash separators outright: they are
	// never legitimate in a pack and path.Clean would not normalise them.
	if strings.ContainsRune(p, '\\') {
		return "", fmt.Errorf("backslash in path %q", p)
	}
	if len(p) >= 2 && p[1] == ':' {
		return "", fmt.Errorf("volume name in path %q", p)
	}
	if strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("absolute path %q", p)
	}
	// Require the path to be already canonical, so a manifest entry and an archive
	// entry are matched byte-for-byte and no "a/../b" or "foo//bar" quietly
	// normalises to something else. path.Clean collapses all of those.
	if clean := path.Clean(p); clean != p {
		return "", fmt.Errorf("path %q is not in canonical form (want %q)", p, clean)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("unsafe segment in path %q", p)
		}
	}
	return p, nil
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// sha256Hex returns the lower-case hex SHA-256 of b.
func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
