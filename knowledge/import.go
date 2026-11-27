package knowledge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// ImportResult summarises what an import indexed, for the operator.
type ImportResult struct {
	PackID         string `json:"pack_id"`
	Version        string `json:"version"`
	KeyID          string `json:"key_id"`
	KeyFingerprint string `json:"key_fingerprint"`
	Exploits       int    `json:"exploits"`
	CVEs           int    `json:"cves"`
	Docs           int    `json:"docs"`
	Templates      int    `json:"templates"`
	Skipped        int    `json:"skipped"`
}

// maxExploitBodyBytes bounds how much of an exploit file is read into the index.
// The file itself is kept on disk for copy_knowledge_file; the index only needs
// enough text to find it.
const maxExploitBodyBytes = 64 << 10

// maxDocBytes bounds how much of a technique/template file is indexed.
const maxDocBytes = 512 << 10

// exploitDBCSV is the ExploitDB index inside a pack. Its "file" column is
// relative to the ExploitDB root (exploits/...), which the pack stores under
// exploitDBPrefix.
const (
	exploitDBPrefix = "exploitdb/"
	exploitDBCSV    = exploitDBPrefix + "files_exploits.csv"
)

// ImportOptions tune an import.
type ImportOptions struct {
	// AllowDowngrade permits importing a version lower than the active one.
	AllowDowngrade bool
	// Repin accepts a pack whose signing key differs from the key pinned for its
	// pack id at first import, and pins the new key. Without it such a pack is
	// refused (key-swap protection, keys.go).
	Repin bool
}

// ErrImportBusy is returned when another import is running.
var ErrImportBusy = errors.New("another knowledge pack import is already running; retry when it finishes")

// stagingPrefix names in-progress extraction directories inside a pack root.
const stagingPrefix = ".staging-"

// Import verifies a pack file, extracts it into a new versioned directory,
// indexes it, and activates it, so that a failure at any step leaves the
// currently active pack — its index rows and its files — untouched (docs §4.1):
//
//  1. verify the signature against the trusted keys before the manifest is
//     parsed, and check the pack id's key pin and the downgrade rule;
//  2. extract to a fresh staging directory (unique per import) and index into
//     an uncommitted transaction;
//  3. rename staging to <packs>/<pack_id>/<version>-<hash>-<n>, a new name
//     that nothing references yet;
//  4. commit: activate the new row, deactivate the old one and set the key pin,
//     atomically;
//  5. only then remove the superseded directories and the superseded rows'
//     index data.
//
// Imports are serialised (ErrImportBusy). keys is the trusted key set
// (production: TrustedKeys).
func (s *Store) Import(ctx context.Context, packPath string, keys map[string]ed25519.PublicKey, opt ImportOptions) (*ImportResult, error) {
	if !s.importMu.TryLock() {
		return nil, ErrImportBusy
	}
	defer s.importMu.Unlock()

	vm, err := VerifyPackFile(packPath, keys)
	if err != nil {
		return nil, err
	}
	if err := s.checkKeyPin(ctx, vm, opt.Repin); err != nil {
		return nil, err
	}
	// Downgrade protection: a validly signed old pack is still stale.
	if active, ok, err := s.ActivePack(ctx, vm.PackID); err != nil {
		return nil, err
	} else if ok && CompareVersions(vm.Version, active) < 0 && !opt.AllowDowngrade {
		return nil, fmt.Errorf("pack %s version %s is older than the active %s; re-import with downgrade allowed to override", vm.PackID, vm.Version, active)
	}

	// pack_id passed ValidID, so it is one safe path segment.
	packRoot := filepath.Join(s.cfg.PacksDir(), vm.PackID)
	if err := os.MkdirAll(packRoot, 0o750); err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(packRoot, stagingPrefix)
	if err != nil {
		return nil, err
	}
	finalName := vm.Version + "-" + sha256Hex(vm.Raw)[:12] + "-" + strings.TrimPrefix(filepath.Base(staging), stagingPrefix)
	final := filepath.Join(packRoot, finalName)
	installed := false // staging renamed to final
	committed := false
	defer func() {
		switch {
		case committed:
		case installed:
			os.RemoveAll(final)
		default:
			os.RemoveAll(staging)
		}
	}()
	if err := ExtractPackFile(packPath, vm.Manifest, staging, ExtractLimits{}); err != nil {
		return nil, err
	}

	ix, err := s.beginImport(ctx, vm, vm.PackID+"/"+finalName)
	if err != nil {
		return nil, err
	}
	res, err := indexPack(ix, vm.Manifest, staging)
	if err != nil {
		ix.rollback()
		return nil, err
	}
	res.KeyID, res.KeyFingerprint = vm.KeyID, vm.Fingerprint
	// The new directory gets a name no row references yet, so the active pack's
	// files are untouched until the commit switches the active row to it.
	if err := os.Rename(staging, final); err != nil {
		ix.rollback()
		return nil, fmt.Errorf("install pack files: %w", err)
	}
	installed = true
	if err := ix.commit(vm, opt.Repin); err != nil {
		return nil, err
	}
	committed = true

	// Superseded data: best effort, after the switch. A failure only leaves
	// unused files or rows behind; the next import retries.
	s.pruneSuperseded(ctx, vm.PackID, packRoot, finalName)
	// Build the vector index in the background (no-op without an embedder or
	// pgvector); search stays lexical until the vectors land.
	s.embedPackAsync(vm.PackID)
	return res, nil
}

// pruneSuperseded removes, after a successful activation, every entry in
// packRoot other than keep (older versions, leftovers of a crashed import) and
// the index rows of the pack id's inactive versions. The pack rows themselves
// stay, as import history with their key fingerprints. Imports are serialised,
// so no other import is writing under packRoot.
func (s *Store) pruneSuperseded(ctx context.Context, packID, packRoot, keep string) {
	if entries, err := os.ReadDir(packRoot); err == nil {
		for _, e := range entries {
			if e.Name() == keep {
				continue
			}
			if err := os.RemoveAll(filepath.Join(packRoot, e.Name())); err != nil {
				log.Printf("[knowledge] remove superseded %s/%s: %v", packID, e.Name(), err)
			}
		}
	}
	if _, err := s.db.ExecContext(ctx, `
DELETE FROM kb_documents WHERE pack_id IN (SELECT id FROM kb_packs WHERE pack_id=$1 AND NOT active)`, packID); err != nil {
		log.Printf("[knowledge] remove superseded index rows of %s: %v", packID, err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE kb_packs SET dir='' WHERE pack_id=$1 AND NOT active`, packID); err != nil {
		log.Printf("[knowledge] clear superseded dirs of %s: %v", packID, err)
	}
}

// indexPack reads an extracted pack's data files and populates the index through
// ix. Files are visited in sorted path order (CVEs, then exploits, then
// docs/templates), so a re-import inserts the same documents in the same order.
func indexPack(ix *indexer, m *Manifest, dir string) (*ImportResult, error) {
	res := &ImportResult{PackID: m.PackID, Version: m.Version}
	files := m.fileByPath()
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	// NVD: every file under nvd/ ending in .json is an NVD 2.0 snapshot.
	for _, p := range paths {
		if !strings.HasPrefix(p, "nvd/") || !strings.HasSuffix(p, ".json") {
			continue
		}
		n, err := indexNVDFile(ix, filepath.Join(dir, filepath.FromSlash(p)))
		if err != nil {
			return nil, fmt.Errorf("index %s: %w", p, err)
		}
		res.CVEs += n
	}

	// ExploitDB: the CSV index, with each exploit's file body chunked when present.
	if _, ok := files[exploitDBCSV]; ok {
		n, skipped, err := indexExploitDB(ix, dir, files)
		if err != nil {
			return nil, fmt.Errorf("index exploitdb: %w", err)
		}
		res.Exploits, res.Skipped = n, skipped
	}

	// Technique docs and templates: every file under docs/ or templates/.
	for _, p := range paths {
		switch {
		case strings.HasPrefix(p, "docs/"):
			if err := indexTextFile(ix, "doc", dir, p); err != nil {
				return nil, fmt.Errorf("index %s: %w", p, err)
			}
			res.Docs++
		case strings.HasPrefix(p, "templates/"):
			if err := indexTextFile(ix, "template", dir, p); err != nil {
				return nil, fmt.Errorf("index %s: %w", p, err)
			}
			res.Templates++
		}
	}
	return res, nil
}

// indexNVDFile streams one NVD file into the index: a cve document plus its CPE
// applicability rows.
func indexNVDFile(ix *indexer, path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	err = ParseNVD(f, func(c CVE) error {
		meta := &docMeta{Published: c.Published, CVSS: c.CVSS, CWEs: c.CWEs, References: c.References}
		cpeTags := make([]string, 0, len(c.CPEMatches))
		for _, m := range c.CPEMatches {
			if p, ok := ParseCPE(m.Criteria); ok {
				cpeTags = append(cpeTags, p.Vendor+":"+p.Product)
			}
		}
		docID, err := ix.addDocument("cve", c.ID, "", c.Description, []string{c.ID}, dedupe(cpeTags), meta, "")
		if err != nil {
			return err
		}
		for _, m := range c.CPEMatches {
			if err := ix.addCPEMatch(docID, m); err != nil {
				return err
			}
		}
		n++
		return nil
	})
	return n, err
}

// indexExploitDB reads files_exploits.csv and indexes each exploit, chunking the
// exploit file body when the pack carries it. The CSV's file column is relative
// to the ExploitDB root (exploits/linux/remote/42.c), so the pack path is
// exploitdb/ + that; an exploit whose file is not in the pack (or whose path is
// unsafe) is indexed on its metadata alone, with no source path.
func indexExploitDB(ix *indexer, dir string, files map[string]FileEntry) (indexed, skipped int, err error) {
	f, err := os.Open(filepath.Join(dir, filepath.FromSlash(exploitDBCSV)))
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	exploits, skip, err := ParseExploitDB(f)
	if err != nil {
		return 0, 0, err
	}
	for _, ex := range exploits {
		sourcePath, body := "", ""
		if clean, perr := SafePath(ex.File); perr == nil {
			if _, inPack := files[exploitDBPrefix+clean]; inPack {
				sourcePath = exploitDBPrefix + clean
				body = readBodyFile(filepath.Join(dir, filepath.FromSlash(sourcePath)), maxExploitBodyBytes)
			}
		}
		em := exploitMeta{
			Type: ex.Type, Platform: ex.Platform, Date: ex.DatePub,
			Port: ex.Port, Author: ex.Author, Verified: ex.Verified,
		}
		if _, err := ix.addDocument("exploit", ex.EDBID, sourcePath, ex.Description, ex.CVEs, nil, em, body); err != nil {
			return 0, 0, err
		}
		indexed++
	}
	return indexed, skip, nil
}

// indexTextFile indexes a technique doc or template: the file content chunked,
// with the title taken from the first markdown heading or the file name.
func indexTextFile(ix *indexer, kind, dir, p string) error {
	body := readBodyFile(filepath.Join(dir, filepath.FromSlash(p)), maxDocBytes)
	title := docTitle(p, body)
	_, err := ix.addDocument(kind, "", p, title, nil, nil, nil, body)
	return err
}

// docTitle derives a document title: the first markdown '# ' heading in body,
// else the file's base name without extension.
func docTitle(p, body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			return strings.TrimSpace(line[2:])
		}
		if line != "" {
			break
		}
	}
	base := filepath.Base(filepath.FromSlash(p))
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// binarySniffBytes is how much of a file is checked for NUL bytes to decide it
// is binary (the same heuristic git and grep use).
const binarySniffBytes = 8 << 10

// readBodyFile reads up to max bytes of a text file for the index. It returns
// "" for a missing file (an exploit body is optional) and for a binary one
// (a NUL in the first 8 KiB: an ExploitDB .exe/.zip/.pcap is indexed on its
// metadata alone). Text is cut at a rune boundary and made valid UTF-8 without
// NULs, which a Postgres TEXT column refuses.
func readBodyFile(path string, max int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, max)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return ""
	}
	b := buf[:n]
	if bytes.IndexByte(b[:min(len(b), binarySniffBytes)], 0) >= 0 {
		return ""
	}
	if n == max {
		b = trimPartialRune(b)
	}
	return sanitizeText(string(b))
}

// trimPartialRune drops an incomplete UTF-8 sequence a byte limit cut off at
// the end of b.
func trimPartialRune(b []byte) []byte {
	for i := 1; i <= utf8.UTFMax && i <= len(b); i++ {
		c := b[len(b)-i]
		if !utf8.RuneStart(c) {
			continue
		}
		if !utf8.FullRune(b[len(b)-i:]) {
			return b[:len(b)-i]
		}
		break
	}
	return b
}

// sanitizeText makes s storable in a Postgres TEXT column: invalid UTF-8 is
// replaced with U+FFFD and NUL bytes are removed. Pack data is signed but not
// necessarily clean (ExploitDB carries Latin-1 and binary snippets, NVD text
// can carry \u0000), and one bad row must not abort a whole import.
func sanitizeText(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	return s
}

func sanitizeAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = sanitizeText(s)
	}
	return out
}

// sanitizeJSON applies sanitizeText to every string in a JSON document, so
// jsonb (which refuses \u0000) accepts it. Invalid JSON becomes "{}".
func sanitizeJSON(b []byte) []byte {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return []byte("{}")
	}
	out, err := json.Marshal(sanitizeValue(v))
	if err != nil {
		return []byte("{}")
	}
	return out
}

func sanitizeValue(v any) any {
	switch t := v.(type) {
	case string:
		return sanitizeText(t)
	case []any:
		for i := range t {
			t[i] = sanitizeValue(t[i])
		}
		return t
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[sanitizeText(k)] = sanitizeValue(val)
		}
		return out
	}
	return v
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
