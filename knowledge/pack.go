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
	"regexp"
	"sort"
	"strings"
	"time"
)

// ManifestName and SigName are the two fixed entries at a pack's root.
const (
	ManifestName = "manifest.json"
	SigName      = "manifest.sig"
)

// FormatVersion is the manifest format this binary reads; KindKnowledge is the
// only pack kind it imports. Both are mandatory in a manifest, so a pack of
// another kind (e.g. a future tool pack signed with the same key) or a newer
// format is refused instead of being misread as a knowledge pack.
const (
	FormatVersion = 1
	KindKnowledge = "knowledge"
)

// idPattern is the syntax of pack_id, version and key_id: one safe path
// segment that starts with an alphanumeric (so never "." or ".."), at most 64
// bytes. pack_id and version become directory names (config.go), and every
// one of them is shown to the operator, so they are kept boring.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

// ValidID reports whether s is a valid pack_id / version / key_id.
func ValidID(s string) bool { return idPattern.MatchString(s) }

// Manifest is the content of manifest.json. The signature covers the exact bytes
// of this file as written, so the importer verifies before it parses: see
// VerifyManifest.
type Manifest struct {
	// Format is the manifest format version (FormatVersion). Mandatory.
	Format int `json:"format"`
	// Kind is the pack kind (KindKnowledge). Mandatory: a manifest that is
	// validly signed but meant for something else must not import as knowledge.
	Kind string `json:"kind"`
	// PackID is a stable identifier for the knowledge set (e.g. "artex-core").
	// Packs with the same id are versions of the same set; a downgrade is refused
	// unless the operator confirms it (store.go).
	PackID string `json:"pack_id"`
	// Version orders packs of one id. Any monotonic string works; the builder
	// uses the build date, e.g. "2026.11.27".
	Version string `json:"version"`
	// BaseVersion, when set, marks a delta pack: it applies only on top of the
	// active pack of the same id at exactly that version (delta.go). Files then
	// lists only the added and changed files, and Deletions the removed ones.
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
	// Deletions lists paths a delta pack removes from the base (only with
	// BaseVersion).
	Deletions []string `json:"deletions,omitempty"`
	// Embeddings declares precomputed chunk vectors shipped in the pack
	// (embedfile.go). Optional; each set's file is one of Files.
	Embeddings []EmbeddingSet `json:"embeddings,omitempty"`
}

// EmbeddingSet describes one file of precomputed chunk vectors. The importer
// uses a set only when its model and chunking budget match the configured
// embedding model and ARTEX_KNOWLEDGE_MAX_CHUNK_BYTES: vectors are keyed by the
// SHA-256 of the exact chunk text, which depends on both.
type EmbeddingSet struct {
	Path       string `json:"path"`             // pack file under embeddings/
	Model      string `json:"model"`            // embedding model name, as configured on import
	Dimension  int    `json:"dimension"`        // vector length
	ChunkBytes int    `json:"chunk_bytes"`      // chunking budget the chunks were cut with
	Count      int    `json:"count"`            // number of vectors in the file
	Digest     string `json:"digest,omitempty"` // model digest, when the builder knew it (informational)
}

// embeddingsPrefix is where precomputed vector files live in a pack.
const embeddingsPrefix = "embeddings/"

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
	if m.Format != FormatVersion {
		return fmt.Errorf("manifest: format %d is not supported (this ARTEX reads format %d)", m.Format, FormatVersion)
	}
	if m.Kind != KindKnowledge {
		return fmt.Errorf("manifest: kind %q is not a knowledge pack (want %q)", m.Kind, KindKnowledge)
	}
	for _, f := range []struct{ name, v string }{{"pack_id", m.PackID}, {"version", m.Version}, {"key_id", m.KeyID}} {
		if !ValidID(f.v) {
			return fmt.Errorf("manifest: %s %q is invalid (1-64 characters from A-Z a-z 0-9 . _ + -, starting with a letter or digit)", f.name, f.v)
		}
	}
	// A delta names the version it applies to, which must be older than its own;
	// deletions exist only in a delta.
	if m.BaseVersion != "" {
		if !ValidID(m.BaseVersion) {
			return fmt.Errorf("manifest: base_version %q is invalid", m.BaseVersion)
		}
		if CompareVersions(m.Version, m.BaseVersion) <= 0 {
			return fmt.Errorf("manifest: delta version %s must be newer than its base %s", m.Version, m.BaseVersion)
		}
	} else if len(m.Deletions) > 0 {
		return fmt.Errorf("manifest: deletions are only valid in a delta pack (with base_version)")
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
	deleted := make(map[string]bool, len(m.Deletions))
	for _, d := range m.Deletions {
		clean, err := SafePath(d)
		if err != nil {
			return fmt.Errorf("manifest: deletion %q: %w", d, err)
		}
		if seen[clean] {
			return fmt.Errorf("manifest: %q is both a file and a deletion", clean)
		}
		if deleted[clean] {
			return fmt.Errorf("manifest: duplicate deletion %q", clean)
		}
		deleted[clean] = true
	}
	for _, e := range m.Embeddings {
		clean, err := SafePath(e.Path)
		if err != nil || !strings.HasPrefix(clean, embeddingsPrefix) {
			return fmt.Errorf("manifest: embedding set path %q must be a file under %s", e.Path, embeddingsPrefix)
		}
		// A full pack carries its sets; a delta may declare a set only for a file
		// it ships (sets of the base are carried over by the merge).
		if !seen[clean] {
			return fmt.Errorf("manifest: embedding set %q is not one of the pack's files", clean)
		}
		if strings.TrimSpace(e.Model) == "" || e.Dimension < 1 || e.Dimension > maxEmbeddingDim || e.ChunkBytes < 16 || e.Count < 0 {
			return fmt.Errorf("manifest: embedding set %q has an invalid model, dimension, chunk_bytes or count", clean)
		}
	}
	return nil
}

// maxEmbeddingDim is pgvector's HNSW limit (vector.go).
const maxEmbeddingDim = 2000

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

// VerifyManifest checks sig against manifestBytes with pub.
func VerifyManifest(pub ed25519.PublicKey, manifestBytes, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("verify: public key is not %d bytes", ed25519.PublicKeySize)
	}
	if !ed25519.Verify(pub, manifestBytes, sig) {
		return fmt.Errorf("verify: manifest signature does not match the trusted key")
	}
	return nil
}

// KeyFingerprint is the lower-case hex SHA-256 of an ed25519 public key: what
// the operator compares and what a pack id is pinned to (store.go).
func KeyFingerprint(pub ed25519.PublicKey) string { return sha256Hex(pub) }

// VerifiedManifest is a manifest whose exact bytes were verified by a trusted
// key before they were parsed.
type VerifiedManifest struct {
	*Manifest
	Raw         []byte // the signed manifest.json bytes
	KeyID       string // id of the trusted key that verified them
	Fingerprint string // KeyFingerprint of that key
}

// VerifyRaw verifies manifestBytes against the trusted keys BEFORE parsing them:
// each key is tried on the raw bytes, and only bytes some trusted key signed are
// parsed and validated. The manifest's own key_id must then name a key that
// verified it, so a pack cannot claim a different signer than the one that
// actually signed it. keys maps key_id to public key (TrustedKeys).
func VerifyRaw(keys map[string]ed25519.PublicKey, manifestBytes, sig []byte) (*VerifiedManifest, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("no knowledge signing key is trusted: embed one in the binary or set %s (a pack is only trusted if a key can verify it)", PubKeyEnv)
	}
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	verified := map[string]ed25519.PublicKey{}
	for _, id := range ids {
		if VerifyManifest(keys[id], manifestBytes, sig) == nil {
			verified[id] = keys[id]
		}
	}
	if len(verified) == 0 {
		return nil, fmt.Errorf("verify: the manifest signature does not match any trusted key")
	}
	m, err := ParseManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	pub, ok := verified[m.KeyID]
	if !ok {
		return nil, fmt.Errorf("verify: the manifest names key_id %q, but it was signed by a different trusted key", m.KeyID)
	}
	return &VerifiedManifest{Manifest: m, Raw: manifestBytes, KeyID: m.KeyID, Fingerprint: KeyFingerprint(pub)}, nil
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
