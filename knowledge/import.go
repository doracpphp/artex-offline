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
	BaseVersion    string `json:"base_version,omitempty"` // set when the pack was a delta
	KeyID          string `json:"key_id"`
	KeyFingerprint string `json:"key_fingerprint"`
	Exploits       int    `json:"exploits"`
	CVEs           int    `json:"cves"`
	Docs           int    `json:"docs"`
	Templates      int    `json:"templates"`
	Skipped        int    `json:"skipped"`
	// Carried is how many chunk vectors were reused from the previous version
	// (unchanged chunk text), so they need no new embedding.
	Carried int `json:"carried_vectors,omitempty"`
	// Warnings are non-fatal findings the operator should see (e.g. a
	// nuclei-templates version that differs from the image's).
	Warnings []string `json:"warnings,omitempty"`
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
	// ImageTemplatesVersion is the nuclei-templates version baked into this
	// installation's image ("" when there is none, e.g. a native run). A pack
	// with templates of another version imports with a warning (docs §5).
	ImageTemplatesVersion string
}

// ErrImportBusy is returned when another import is running.
var ErrImportBusy = errors.New("another knowledge pack import is already running; retry when it finishes")

// stagingPrefix names in-progress extraction directories inside a pack root.
const stagingPrefix = ".staging-"

// Import verifies a pack file, builds its new versioned directory, indexes it,
// and activates it, so that a failure at any step leaves the currently active
// pack — its index rows and its files — untouched (docs §4.1):
//
//  1. verify the signature against the trusted keys before the manifest is
//     parsed, and check the pack id's key pin and the version rule (a full
//     pack must not be a downgrade; a delta must apply to the active version);
//  2. extract to a fresh staging directory (unique per import); for a delta,
//     complete it with the base version's unchanged files (delta.go); store
//     the manifest the directory was indexed from as manifest.json;
//  3. index into an uncommitted transaction, then rename staging to
//     <packs>/<pack_id>/<version>-<hash>-<n>, a name nothing references yet;
//  4. commit: activate the new row, deactivate the old one and set the key pin,
//     atomically;
//  5. reuse the old version's vectors for unchanged chunks, then remove the
//     superseded directories and index rows.
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
	active, hasActive, err := s.activePackRow(ctx, vm.PackID)
	if err != nil {
		return nil, err
	}
	if vm.BaseVersion != "" {
		// A delta applies to exactly its base: anything else would merge it onto
		// files it was not computed against.
		if !hasActive || active.Version != vm.BaseVersion {
			cur := "no active version"
			if hasActive {
				cur = "the active version is " + active.Version
			}
			return nil, fmt.Errorf("pack %s %s is a delta for base version %s, but %s; import the full pack of %s (or a delta built against the active version) first", vm.PackID, vm.Version, vm.BaseVersion, cur, vm.BaseVersion)
		}
	} else if hasActive && CompareVersions(vm.Version, active.Version) < 0 && !opt.AllowDowngrade {
		// Downgrade protection: a validly signed old pack is still stale.
		return nil, fmt.Errorf("pack %s version %s is older than the active %s; re-import with downgrade allowed to override", vm.PackID, vm.Version, active.Version)
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
	var final string
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

	// The manifest this directory is indexed from: the signed one for a full
	// pack, the merged one for a delta. It is stored with the files so a later
	// delta can build on it, and its hash goes into kb_packs.
	merged, manifestBytes := vm.Manifest, vm.Raw
	if vm.BaseVersion != "" {
		baseDir, err := s.cfg.packFilesDir(active.Dir)
		if err != nil {
			return nil, err
		}
		base, err := readStoredManifest(baseDir, active.ManifestSHA)
		if err != nil {
			return nil, err
		}
		if merged, err = applyDelta(baseDir, base, vm.Manifest, staging); err != nil {
			return nil, err
		}
		if manifestBytes, err = merged.Marshal(); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(staging, storedManifestName), manifestBytes, 0o640); err != nil {
		return nil, err
	}
	manifestSHA := sha256Hex(manifestBytes)
	finalName := vm.Version + "-" + manifestSHA[:12] + "-" + strings.TrimPrefix(filepath.Base(staging), stagingPrefix)
	final = filepath.Join(packRoot, finalName)

	ix, err := s.beginImport(ctx, vm, merged, manifestSHA, vm.PackID+"/"+finalName)
	if err != nil {
		return nil, err
	}
	res, err := indexPack(ix, viewOf(merged, staging))
	if err != nil {
		ix.rollback()
		return nil, err
	}
	res.PackID, res.Version, res.BaseVersion = vm.PackID, vm.Version, vm.BaseVersion
	res.KeyID, res.KeyFingerprint = vm.KeyID, vm.Fingerprint
	res.Warnings = templateWarnings(merged, opt.ImageTemplatesVersion, res.Templates)
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

	// Vectors of unchanged chunks are reused before the old version's rows go;
	// both steps are best effort (a failure costs re-embedding or leaves unused
	// rows behind, which the next import retries).
	res.Carried = s.carryOverEmbeddings(ctx, vm.PackID)
	s.pruneSuperseded(ctx, vm.PackID, packRoot, finalName)
	// Build the remaining vectors in the background (no-op without an embedder or
	// pgvector): precomputed vectors shipped in the pack first, then the
	// embedding model. Search stays lexical until vectors land.
	s.embedPackAsync(vm.PackID)
	return res, nil
}

// templateWarnings compares the nuclei-templates version recorded in the pack
// with the one baked into the image (docs §5): search results point at
// templates by path, and only the image's own set can run them.
func templateWarnings(m *Manifest, imageVersion string, templates int) []string {
	if templates == 0 {
		return nil
	}
	packVersion := ""
	for _, src := range m.Sources {
		if src.Name == "nuclei-templates" {
			packVersion = strings.TrimSpace(src.Version)
		}
	}
	imageVersion = templatesTag(imageVersion)
	switch {
	case imageVersion == "":
		return []string{"this installation has no baked nuclei-templates (no tool inventory entry): template hits carry no local_path to run"}
	case packVersion == "":
		return []string{fmt.Sprintf("the pack does not record its nuclei-templates version; the image has %s, so a template hit may name a template the local nuclei does not have (local_path is given only when the file exists)", imageVersion)}
	case templatesTag(packVersion) != imageVersion:
		return []string{fmt.Sprintf("the pack's nuclei-templates %s differ from the image's %s: a template hit may name a template the local nuclei does not have, or a different revision of it (local_path is given only when the file exists)", packVersion, imageVersion)}
	}
	return nil
}

// templatesTag is the release tag of a templates version string: the tool
// inventory records "v10.5.1 (<commit>)".
func templatesTag(v string) string {
	if f := strings.Fields(v); len(f) > 0 {
		return f[0]
	}
	return ""
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

// docSink receives the documents of a pack as they are parsed: the import's
// database indexer, or the builder's chunk collector (embedfile.go), so both
// see exactly the same documents and chunks.
type docSink interface {
	addDocument(kind, extID, sourcePath, title string, cveIDs, cpeTags []string, meta any, bodyText string) (int64, error)
	addCPEMatch(docID int64, m CPEMatch) error
}

// packView is a pack's file set: its sorted paths and where each file is on
// disk (the extracted directory on import, the source files in the builder).
type packView struct {
	paths   []string
	has     map[string]bool
	resolve func(packPath string) string
}

// viewOf is the view of an extracted pack directory with manifest m.
func viewOf(m *Manifest, dir string) packView {
	files := m.fileByPath()
	v := packView{has: make(map[string]bool, len(files)), resolve: func(p string) string {
		return filepath.Join(dir, filepath.FromSlash(p))
	}}
	for p := range files {
		v.paths = append(v.paths, p)
		v.has[p] = true
	}
	sort.Strings(v.paths)
	return v
}

// viewOfFiles is the view of a builder input (pack path -> source file).
func viewOfFiles(files map[string]string) packView {
	v := packView{has: make(map[string]bool, len(files)), resolve: func(p string) string { return files[p] }}
	for p := range files {
		v.paths = append(v.paths, p)
		v.has[p] = true
	}
	sort.Strings(v.paths)
	return v
}

// indexPack reads a pack's data files and feeds them to ix. Files are visited
// in sorted path order (CVEs, then exploits, then docs/templates), so a
// re-import inserts the same documents in the same order.
func indexPack(ix docSink, v packView) (*ImportResult, error) {
	res := &ImportResult{}

	// NVD: every file under nvd/ ending in .json is an NVD 2.0 snapshot.
	for _, p := range v.paths {
		if !strings.HasPrefix(p, "nvd/") || !strings.HasSuffix(p, ".json") {
			continue
		}
		n, err := indexNVDFile(ix, v.resolve(p))
		if err != nil {
			return nil, fmt.Errorf("index %s: %w", p, err)
		}
		res.CVEs += n
	}

	// ExploitDB: the CSV index, with each exploit's file body chunked when present.
	if v.has[exploitDBCSV] {
		n, skipped, err := indexExploitDB(ix, v)
		if err != nil {
			return nil, fmt.Errorf("index exploitdb: %w", err)
		}
		res.Exploits, res.Skipped = n, skipped
	}

	// Technique docs and templates: every file under docs/ or templates/.
	for _, p := range v.paths {
		switch {
		case strings.HasPrefix(p, "docs/"):
			if err := indexTextFile(ix, "doc", v.resolve(p), p); err != nil {
				return nil, fmt.Errorf("index %s: %w", p, err)
			}
			res.Docs++
		case strings.HasPrefix(p, templatesPrefix):
			if err := indexTemplateFile(ix, v.resolve(p), p); err != nil {
				return nil, fmt.Errorf("index %s: %w", p, err)
			}
			res.Templates++
		}
	}
	return res, nil
}

// indexNVDFile streams one NVD file into the index: a cve document plus its CPE
// applicability rows.
func indexNVDFile(ix docSink, path string) (int, error) {
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
func indexExploitDB(ix docSink, v packView) (indexed, skipped int, err error) {
	f, err := os.Open(v.resolve(exploitDBCSV))
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
		if clean, perr := SafePath(ex.File); perr == nil && v.has[exploitDBPrefix+clean] {
			sourcePath = exploitDBPrefix + clean
			body = readBodyFile(v.resolve(sourcePath), maxExploitBodyBytes)
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

// indexTextFile indexes a technique doc: the file content chunked, with the
// title taken from the first markdown heading or the file name.
func indexTextFile(ix docSink, kind, file, p string) error {
	body := readBodyFile(file, maxDocBytes)
	title := docTitle(p, body)
	_, err := ix.addDocument(kind, "", p, title, nil, nil, nil, body)
	return err
}

// indexTemplateFile indexes a file under templates/. A nuclei template (YAML
// with an id) gets its id as ext_id, its name as title, its CVEs (so lookup_cve
// links it) and vendor:product, and severity/tags in meta; anything else in the
// templates tree (helpers, payload lists) is indexed as plain text.
func indexTemplateFile(ix docSink, file, p string) error {
	body := readBodyFile(file, maxDocBytes)
	ext := strings.ToLower(filepath.Ext(p))
	t, ok := NucleiTemplate{}, false
	if ext == ".yaml" || ext == ".yml" {
		t, ok = ParseNucleiTemplate([]byte(body))
	}
	if !ok {
		_, err := ix.addDocument("template", "", p, docTitle(p, body), nil, nil, nil, body)
		return err
	}
	title := t.Name
	if title == "" {
		title = t.ID
	}
	var cpeTags []string
	if t.Vendor != "" && t.Product != "" {
		cpeTags = []string{t.Vendor + ":" + t.Product}
	}
	meta := templateMeta{TemplateID: t.ID, Severity: t.Severity, Tags: t.Tags, CWEs: t.CWEs}
	_, err := ix.addDocument("template", t.ID, p, title, t.CVEs, cpeTags, meta, body)
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
