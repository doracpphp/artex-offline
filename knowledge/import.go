package knowledge

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ImportResult summarises what an import indexed, for the operator.
type ImportResult struct {
	PackID    string `json:"pack_id"`
	Version   string `json:"version"`
	Exploits  int    `json:"exploits"`
	CVEs      int    `json:"cves"`
	Docs      int    `json:"docs"`
	Templates int    `json:"templates"`
	Skipped   int    `json:"skipped"`
}

// maxExploitBodyBytes bounds how much of an exploit file is read into the index.
// The file itself is kept on disk for copy_knowledge_file; the index only needs
// enough text to find it.
const maxExploitBodyBytes = 64 << 10

// maxDocBytes bounds how much of a technique/template file is indexed.
const maxDocBytes = 512 << 10

// ImportOptions tune an import.
type ImportOptions struct {
	// AllowDowngrade permits importing a version lower than the active one.
	AllowDowngrade bool
}

// Import verifies a pack file, extracts it to staging, indexes it, puts its
// files in place, and activates it — all so that a failure leaves the currently
// active pack untouched (docs §4.1). trust resolves the manifest's key_id to a
// public key (production: pass a wrapper over TrustedKey). It returns a summary.
func (s *Store) Import(ctx context.Context, packPath string, trust func(keyID string) ([]byte, error), opt ImportOptions) (*ImportResult, error) {
	m, err := VerifyPackFile(packPath, trust)
	if err != nil {
		return nil, err
	}
	// Downgrade protection: a validly signed old pack is still stale.
	if active, ok, err := s.ActivePack(ctx, m.PackID); err != nil {
		return nil, err
	} else if ok && CompareVersions(m.Version, active) < 0 && !opt.AllowDowngrade {
		return nil, fmt.Errorf("pack %s version %s is older than the active %s; re-import with downgrade allowed to override", m.PackID, m.Version, active)
	}

	staging := filepath.Join(s.cfg.StagingDir(), sanitizeID(m.PackID))
	if err := os.RemoveAll(staging); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return nil, err
	}
	// Clean staging on any failure; on success it has been renamed away.
	committed := false
	defer func() {
		if !committed {
			os.RemoveAll(staging)
		}
	}()
	if err := ExtractPackFile(packPath, m, staging, ExtractLimits{}); err != nil {
		return nil, err
	}

	manifestBytes, err := manifestBytesOf(packPath)
	if err != nil {
		return nil, err
	}
	ix, err := s.beginImport(ctx, m, sha256Hex(manifestBytes))
	if err != nil {
		return nil, err
	}
	res, err := indexPack(ix, m, staging)
	if err != nil {
		ix.rollback()
		return nil, err
	}

	// Put the files in place before committing, so an active pack never points at
	// a staging directory. A rename failure aborts the import.
	final := s.cfg.PackDir(sanitizeID(m.PackID))
	if err := replaceDir(staging, final); err != nil {
		ix.rollback()
		return nil, fmt.Errorf("install pack files: %w", err)
	}
	if err := ix.commit(m.PackID); err != nil {
		return nil, err
	}
	committed = true
	// Build the vector index in the background (no-op without an embedder or
	// pgvector); search stays lexical until the vectors land.
	s.embedPackAsync(m.PackID)
	return res, nil
}

// indexPack reads an extracted pack's data files and populates the index through
// ix. The order is deterministic (CVEs, then exploits, then docs/templates) so a
// re-import produces the same ids.
func indexPack(ix *indexer, m *Manifest, dir string) (*ImportResult, error) {
	res := &ImportResult{PackID: m.PackID, Version: m.Version}
	files := m.fileByPath()

	// NVD: every file under nvd/ ending in .json is an NVD 2.0 snapshot.
	for p := range files {
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
	if _, ok := files["exploitdb/files_exploits.csv"]; ok {
		n, skipped, err := indexExploitDB(ix, dir)
		if err != nil {
			return nil, fmt.Errorf("index exploitdb: %w", err)
		}
		res.Exploits, res.Skipped = n, skipped
	}

	// Technique docs and templates: every file under docs/ or templates/.
	for p := range files {
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
// exploit file body when it is present under the pack directory.
func indexExploitDB(ix *indexer, dir string) (indexed, skipped int, err error) {
	csvPath := filepath.Join(dir, "exploitdb", "files_exploits.csv")
	f, err := os.Open(csvPath)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	exploits, skip, err := ParseExploitDB(f)
	if err != nil {
		return 0, 0, err
	}
	for _, ex := range exploits {
		body := readBodyFile(filepath.Join(dir, filepath.FromSlash(ex.File)), maxExploitBodyBytes)
		em := exploitMeta{
			Type: ex.Type, Platform: ex.Platform, Date: ex.DatePub,
			Port: ex.Port, Author: ex.Author, Verified: ex.Verified,
		}
		if _, err := ix.addDocument("exploit", ex.EDBID, ex.File, ex.Description, ex.CVEs, nil, em, body); err != nil {
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

// readBodyFile reads up to max bytes of a file, returning "" on any error (a
// missing exploit body is normal; indexing continues on metadata alone).
func readBodyFile(path string, max int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, max)
	n, _ := f.Read(buf)
	return string(buf[:n])
}

// replaceDir atomically-ish replaces dst with src: it removes dst, then renames
// src onto it (both on the same filesystem, under the data directory).
func replaceDir(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	return os.Rename(src, dst)
}

// sanitizeID makes a pack id safe as a single path segment (it is operator/
// builder-controlled, but never trust it as a path). SafePath on a single
// segment rejects slashes and traversal.
func sanitizeID(id string) string {
	if _, err := SafePath(id); err == nil && !strings.Contains(id, "/") {
		return id
	}
	// Fall back to a filtered form; the pack still works, only its directory name
	// differs from the id.
	var b strings.Builder
	for _, r := range id {
		if r == '-' || r == '_' || r == '.' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "pack"
	}
	return b.String()
}

// manifestBytesOf reads a pack file's raw manifest.json bytes (for the pack
// row's manifest hash).
func manifestBytesOf(packPath string) ([]byte, error) {
	f, err := os.Open(packPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, _, err := ReadManifest(f)
	return b, err
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
