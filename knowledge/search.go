package knowledge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Query results for the agent tools. Every result carries a Source string of the
// form "pack-id:path[:chunk]" so the model copies a traceable citation into a
// finding's evidence (docs §4.3).

// PackRow is one imported pack, for the management UI.
type PackRow struct {
	PackID         string    `json:"pack_id"`
	Version        string    `json:"version"`
	KeyID          string    `json:"key_id"`
	KeyFingerprint string    `json:"key_fingerprint"` // SHA-256 of the key that verified the manifest
	FileCount      int       `json:"file_count"`
	Active         bool      `json:"active"`
	ImportedAt     time.Time `json:"imported_at"`
}

// ExploitHit is one search_exploits result.
type ExploitHit struct {
	EDBID    string   `json:"edb_id"`
	Title    string   `json:"title"`
	Type     string   `json:"type,omitempty"`
	Platform string   `json:"platform,omitempty"`
	Date     string   `json:"date,omitempty"`
	Verified bool     `json:"verified"`
	CVEs     []string `json:"cves,omitempty"`
	Path     string   `json:"path,omitempty"`
	Snippet  string   `json:"snippet,omitempty"`
	Source   string   `json:"source"`
}

// TechniqueHit is one search_technique result: a technique doc, or a nuclei
// template (Kind "template", with its id, severity and, when this installation
// has the same file, the local path to run it with nuclei -t).
type TechniqueHit struct {
	Kind       string `json:"kind"`
	Title      string `json:"title"`
	Path       string `json:"path"`
	Chunk      int    `json:"chunk"`
	TemplateID string `json:"template_id,omitempty"`
	Severity   string `json:"severity,omitempty"`
	LocalPath  string `json:"local_path,omitempty"`
	Snippet    string `json:"snippet"`
	Source     string `json:"source"`
}

// TemplateRef links a CVE to a nuclei template that detects it.
type TemplateRef struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Severity  string `json:"severity,omitempty"`
	Path      string `json:"path"`                 // pack path (read_knowledge / copy_knowledge_file)
	LocalPath string `json:"local_path,omitempty"` // this installation's copy, for nuclei -t
}

// CVEInfo is the lookup_cve result.
type CVEInfo struct {
	ID          string        `json:"id"`
	Description string        `json:"description"`
	CVSS        *CVSS         `json:"cvss,omitempty"`
	CWEs        []string      `json:"cwes,omitempty"`
	References  []string      `json:"references,omitempty"`
	Exploits    []ExploitRef  `json:"exploits,omitempty"`
	Templates   []TemplateRef `json:"templates,omitempty"`
	Source      string        `json:"source"`
}

// ExploitRef links a CVE to an exploit that references it.
type ExploitRef struct {
	EDBID string `json:"edb_id"`
	Title string `json:"title"`
	Path  string `json:"path,omitempty"`
}

// SoftwareHit is one lookup_software result: a CVE whose CPE applicability
// matches the queried product and version.
type SoftwareHit struct {
	CVE         string   `json:"cve"`
	Description string   `json:"description"`
	CVSS        *CVSS    `json:"cvss,omitempty"`
	MatchedCPE  string   `json:"matched_cpe"`
	CWEs        []string `json:"cwes,omitempty"`
	Vendor      string   `json:"vendor"`
	Product     string   `json:"product"`
	// MatchBasis says how the product matched: "exact" (the CPE product equals
	// the query) or "partial" (the query is a substring of the CPE product, used
	// only when nothing matched exactly). A partial match can be a different
	// product; check Vendor/Product before relying on it.
	MatchBasis string `json:"match_basis"`
	// VersionChecked is true when a version was given and the CPE range was
	// evaluated against it; false means "any version of this product".
	VersionChecked bool   `json:"version_checked"`
	Source         string `json:"source"`
}

// KnowledgeChunk is a read_knowledge result: one chunk's full text.
type KnowledgeChunk struct {
	Title       string `json:"title"`
	Path        string `json:"path,omitempty"`
	Chunk       int    `json:"chunk"`
	TotalChunks int    `json:"total_chunks"`
	Text        string `json:"text"`
	Source      string `json:"source"`
}

// packByDoc caches the active pack id per query so a Source string can be built
// without joining it into every row; there is one active pack per pack_id but
// documents can come from different packs, so we read the pack_id alongside.

// SearchExploits runs a hybrid lexical search over exploit documents (the CSV
// metadata and, when present, the chunked file body), plus optional type and
// platform filters. It returns the top chunks as exploit hits, de-duplicated to
// one hit per exploit (the best-ranked chunk), newest rank first.
func (s *Store) SearchExploits(ctx context.Context, query, typ, platform string, limit int) ([]ExploitHit, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}
	limit = clampLimit(limit, s.cfg.MaxChunks)
	rows, err := s.searchChunks(ctx, []string{"exploit"}, query, strings.ToLower(typ), strings.ToLower(platform), limit)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []ExploitHit
	for _, r := range rows {
		edb := r.extID.String
		if seen[edb] {
			continue
		}
		seen[edb] = true
		em := exploitMetaOf(r.metaRaw)
		out = append(out, ExploitHit{
			EDBID:    edb,
			Title:    r.title.String,
			Type:     em.Type,
			Platform: em.Platform,
			Date:     em.Date,
			Verified: em.Verified,
			CVEs:     parsePGTextArray(r.cveArr.String),
			Path:     r.sourcePath.String,
			Snippet:  snippet(r.body, query, 240),
			Source:   source(r.packID, r.sourcePath.String, r.chunkIndex),
		})
	}
	return out, nil
}

// exploitMeta is the kb_documents.meta shape for an exploit document.
type exploitMeta struct {
	Type     string `json:"type,omitempty"`
	Platform string `json:"platform,omitempty"`
	Date     string `json:"date,omitempty"`
	Port     string `json:"port,omitempty"`
	Author   string `json:"author,omitempty"`
	Verified bool   `json:"verified,omitempty"`
}

// SearchTechnique runs a hybrid lexical search over technique documents (docs/).
func (s *Store) SearchTechnique(ctx context.Context, query string, limit int) ([]TechniqueHit, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}
	rows, err := s.searchChunks(ctx, []string{"doc", "template"}, query, "", "", limit)
	if err != nil {
		return nil, err
	}
	var out []TechniqueHit
	for _, r := range rows {
		h := TechniqueHit{
			Kind:    r.kind,
			Title:   r.title.String,
			Path:    r.sourcePath.String,
			Chunk:   r.chunkIndex,
			Snippet: snippet(r.body, query, 300),
			Source:  source(r.packID, r.sourcePath.String, r.chunkIndex),
		}
		if r.kind == "template" {
			var tm templateMeta
			_ = json.Unmarshal(r.metaRaw, &tm)
			h.TemplateID, h.Severity = tm.TemplateID, tm.Severity
			h.LocalPath = s.localTemplatePath(h.Path)
		}
		out = append(out, h)
	}
	return out, nil
}

// localTemplatePath maps a pack template path (templates/<rel>) to this
// installation's copy (<NUCLEI_TEMPLATES_DIR>/<rel>), or "" when there is no
// such file. The pack and image layouts match (nuclei.go); the file must exist,
// so a version mismatch never yields a path nuclei cannot open.
func (s *Store) localTemplatePath(packPath string) string {
	if s.cfg.TemplatesDir == "" || !strings.HasPrefix(packPath, templatesPrefix) {
		return ""
	}
	rel, err := SafePath(strings.TrimPrefix(packPath, templatesPrefix))
	if err != nil {
		return ""
	}
	p := filepath.Join(s.cfg.TemplatesDir, filepath.FromSlash(rel))
	if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	return p
}

// LookupCVE returns one CVE's structured record, the exploits that reference
// it and the nuclei templates that detect it. ok is false when the active pack
// knows nothing about the CVE; a CVE missing from the NVD data but referenced by
// an exploit or a template is still returned, with those links.
func (s *Store) LookupCVE(ctx context.Context, cve string) (CVEInfo, bool, error) {
	cve = strings.ToUpper(strings.TrimSpace(cve))
	if !cveRe.MatchString(cve) {
		return CVEInfo{}, false, fmt.Errorf("%q is not a CVE id", cve)
	}
	var packID string
	var title sql.NullString
	var metaRaw []byte
	info := CVEInfo{ID: cve}
	found := false
	err := s.db.QueryRowContext(ctx, `
SELECT p.pack_id, d.title, d.meta
FROM kb_documents d
JOIN kb_packs p ON p.id = d.pack_id AND p.active
WHERE d.kind='cve' AND lower(d.ext_id)=lower($1)
LIMIT 1`, cve).Scan(&packID, &title, &metaRaw)
	switch {
	case err == sql.ErrNoRows:
	case err != nil:
		return CVEInfo{}, false, err
	default:
		found = true
		var meta docMeta
		_ = json.Unmarshal(metaRaw, &meta)
		info.Description, info.CVSS, info.CWEs, info.References = title.String, meta.CVSS, meta.CWEs, meta.References
		info.Source = source(packID, "nvd/"+cve, 0)
	}
	if err := s.cveTemplates(ctx, &info); err != nil {
		return info, found, err
	}
	found = found || len(info.Templates) > 0
	// Exploits whose cve_ids contain this CVE.
	exRows, err := s.db.QueryContext(ctx, `
SELECT d.ext_id, d.source_path, d.title
FROM kb_documents d
JOIN kb_packs p ON p.id = d.pack_id AND p.active
WHERE d.kind='exploit' AND $1 = ANY(d.cve_ids)
ORDER BY d.ext_id
LIMIT 50`, cve)
	if err != nil {
		return info, true, err
	}
	defer exRows.Close()
	for exRows.Next() {
		var extID, sp, t sql.NullString
		if err := exRows.Scan(&extID, &sp, &t); err != nil {
			return info, true, err
		}
		info.Exploits = append(info.Exploits, ExploitRef{EDBID: extID.String, Title: t.String, Path: sp.String})
	}
	if err := exRows.Err(); err != nil {
		return info, true, err
	}
	return info, found || len(info.Exploits) > 0, nil
}

// cveTemplates adds the nuclei templates whose classification names the CVE.
func (s *Store) cveTemplates(ctx context.Context, info *CVEInfo) error {
	rows, err := s.db.QueryContext(ctx, `
SELECT d.ext_id, d.title, d.source_path, d.meta
FROM kb_documents d
JOIN kb_packs p ON p.id = d.pack_id AND p.active
WHERE d.kind='template' AND $1 = ANY(d.cve_ids)
ORDER BY d.source_path
LIMIT 20`, info.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, t, sp sql.NullString
		var metaRaw []byte
		if err := rows.Scan(&id, &t, &sp, &metaRaw); err != nil {
			return err
		}
		var tm templateMeta
		_ = json.Unmarshal(metaRaw, &tm)
		info.Templates = append(info.Templates, TemplateRef{
			ID: id.String, Name: t.String, Severity: tm.Severity, Path: sp.String,
			LocalPath: s.localTemplatePath(sp.String),
		})
	}
	return rows.Err()
}

// LookupSoftware resolves a product (and optional vendor and version) to the
// CVEs whose CPE applicability matches. Candidate rows are filtered by
// product/vendor in SQL, then the version range is evaluated in Go
// (CPEMatch.MatchesVersion), which the SQL cannot express for the odd CPE
// version strings. Results are one per CVE, highest CVSS first.
//
// An exact product match (the CPE product equals the query, spaces folded to
// CPE underscores) is preferred: only when there is none are products that
// merely contain the query used, and each hit says which basis it matched on
// (MatchBasis), so "php" does not silently return phpmyadmin CVEs as PHP ones.
// Candidate rows are read in a fixed order, so the same query returns the same
// hits.
func (s *Store) LookupSoftware(ctx context.Context, product, vendor, version string, limit int) ([]SoftwareHit, error) {
	product = strings.Join(strings.Fields(strings.ToLower(product)), "_")
	vendor = strings.Join(strings.Fields(strings.ToLower(vendor)), "_")
	version = strings.TrimSpace(version)
	if product == "" {
		return nil, fmt.Errorf("a product name is required")
	}
	limit = clampLimit(limit, 50)
	hits, err := s.lookupSoftware(ctx, `m.product = $1`, product, vendor, version, "exact")
	if err != nil {
		return nil, err
	}
	if len(hits) == 0 {
		hits, err = s.lookupSoftware(ctx, `m.product LIKE '%' || $1 || '%' ESCAPE '\'`, escapeLike(product), vendor, version, "partial")
		if err != nil {
			return nil, err
		}
	}
	sortByCVSS(hits)
	if len(hits) > limit {
		hits = hits[:limit]
	}
	return hits, nil
}

// maxSoftwareCandidates caps the CPE rows one lookup_software basis reads.
const maxSoftwareCandidates = 5000

func (s *Store) lookupSoftware(ctx context.Context, productCond, product, vendor, version, basis string) ([]SoftwareHit, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT p.pack_id, d.ext_id, d.title, d.meta, m.criteria, m.vendor, m.product,
       m.version_start_including, m.version_start_excluding,
       m.version_end_including, m.version_end_excluding
FROM kb_cpe_matches m
JOIN kb_documents d ON d.id = m.document_id
JOIN kb_packs p ON p.id = d.pack_id AND p.active
WHERE m.vulnerable
  AND `+productCond+`
  AND ($2 = '' OR m.vendor = $2)
ORDER BY m.product, m.vendor, d.ext_id, m.id
LIMIT $3`, product, vendor, maxSoftwareCandidates)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []SoftwareHit
	for rows.Next() {
		var packID, mVendor, mProduct string
		var extID, title sql.NullString
		var metaRaw []byte
		var m CPEMatch
		if err := rows.Scan(&packID, &extID, &title, &metaRaw, &m.Criteria, &mVendor, &mProduct,
			&m.VersionStartIncluding, &m.VersionStartExcluding,
			&m.VersionEndIncluding, &m.VersionEndExcluding); err != nil {
			return nil, err
		}
		if version != "" && !m.MatchesVersion(version) {
			continue
		}
		cve := extID.String
		if seen[cve] {
			continue // first matching CPE row (in the fixed order) represents the CVE
		}
		seen[cve] = true
		var meta docMeta
		_ = json.Unmarshal(metaRaw, &meta)
		out = append(out, SoftwareHit{
			CVE: cve, Description: title.String, CVSS: meta.CVSS, CWEs: meta.CWEs,
			MatchedCPE: m.Criteria, Vendor: mVendor, Product: mProduct,
			MatchBasis: basis, VersionChecked: version != "",
			Source: source(packID, "nvd/"+cve, 0),
		})
	}
	return out, rows.Err()
}

// escapeLike escapes the LIKE metacharacters in s for an ESCAPE '\' pattern,
// so a product name with % or _ (CPE products use _ a lot) matches literally.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// ReadKnowledge returns one chunk's full text, located by a document's source
// path or ext id plus a 1-based chunk index. ok is false when not found.
func (s *Store) ReadKnowledge(ctx context.Context, ref string, chunk int) (KnowledgeChunk, bool, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return KnowledgeChunk{}, false, fmt.Errorf("a document id or source path is required")
	}
	if chunk < 1 {
		chunk = 1
	}
	var packID, body string
	var sourcePath, title sql.NullString
	var total int
	err := s.db.QueryRowContext(ctx, `
SELECT p.pack_id, d.source_path, d.title, c.body,
       (SELECT count(*) FROM kb_chunks x WHERE x.document_id = d.id)
FROM kb_documents d
JOIN kb_packs p ON p.id = d.pack_id AND p.active
JOIN kb_chunks c ON c.document_id = d.id AND c.chunk_index = $2
WHERE (d.source_path = $1 OR lower(d.ext_id) = lower($1))
LIMIT 1`, ref, chunk).Scan(&packID, &sourcePath, &title, &body, &total)
	if err == sql.ErrNoRows {
		return KnowledgeChunk{}, false, nil
	}
	if err != nil {
		return KnowledgeChunk{}, false, err
	}
	// Chunks are cut at this size when imported, but the setting can be lowered
	// later: cut at a rune boundary so multi-byte text stays valid.
	body = truncateUTF8(body, s.cfg.MaxChunkBytes)
	return KnowledgeChunk{
		Title: title.String, Path: sourcePath.String, Chunk: chunk, TotalChunks: total,
		Text: body, Source: source(packID, sourcePath.String, chunk),
	}, true, nil
}

// MaxDocumentFileBytes caps a file copy_knowledge_file copies out of a pack.
// ExploitDB files are small (the largest are a few MB of archives); the cap only
// stops a hostile or broken pack from filling the working directory.
const MaxDocumentFileBytes = 32 << 20

// ReadDocumentFile returns the content of a document's source file, for
// copy_knowledge_file. The file is opened through an os.Root of the active
// pack's directory, so neither the stored directory nor the source path can
// reach outside it (no "..", no symlink out), and it must be a regular file of
// at most maxBytes. ok is false when the document has no file (a CVE) or is
// not found.
func (s *Store) ReadDocumentFile(ctx context.Context, ref string, maxBytes int64) (data []byte, packID, sourcePath string, ok bool, err error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, "", "", false, fmt.Errorf("a document id or source path is required")
	}
	var dir string
	var sp sql.NullString
	err = s.db.QueryRowContext(ctx, `
SELECT p.pack_id, p.dir, d.source_path
FROM kb_documents d
JOIN kb_packs p ON p.id = d.pack_id AND p.active
WHERE (d.source_path = $1 OR lower(d.ext_id) = lower($1)) AND d.source_path IS NOT NULL
ORDER BY d.id
LIMIT 1`, ref).Scan(&packID, &dir, &sp)
	if err == sql.ErrNoRows {
		return nil, "", "", false, nil
	}
	if err != nil {
		return nil, "", "", false, err
	}
	clean, err := SafePath(sp.String)
	if err != nil {
		return nil, "", "", false, err
	}
	absDir, err := s.cfg.packFilesDir(dir)
	if err != nil {
		return nil, "", "", false, err
	}
	root, err := os.OpenRoot(absDir)
	if err != nil {
		return nil, "", "", false, fmt.Errorf("open pack directory: %w", err)
	}
	defer root.Close()
	f, err := root.Open(filepath.FromSlash(clean))
	if err != nil {
		return nil, "", "", false, fmt.Errorf("open pack file %s: %w", clean, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, "", "", false, err
	}
	if !fi.Mode().IsRegular() {
		return nil, "", "", false, fmt.Errorf("pack file %s is not a regular file", clean)
	}
	if fi.Size() > maxBytes {
		return nil, "", "", false, fmt.Errorf("pack file %s is %d bytes, over the %d-byte copy limit", clean, fi.Size(), maxBytes)
	}
	data, err = io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, "", "", false, err
	}
	if int64(len(data)) > maxBytes {
		return nil, "", "", false, fmt.Errorf("pack file %s is over the %d-byte copy limit", clean, maxBytes)
	}
	return data, packID, clean, true, nil
}
