package knowledge

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Query results for the agent tools. Every result carries a Source string of the
// form "pack-id:path[:chunk]" so the model copies a traceable citation into a
// finding's evidence (docs §4.3).

// PackRow is one imported pack, for the management UI.
type PackRow struct {
	PackID     string    `json:"pack_id"`
	Version    string    `json:"version"`
	KeyID      string    `json:"key_id"`
	FileCount  int       `json:"file_count"`
	Active     bool      `json:"active"`
	ImportedAt time.Time `json:"imported_at"`
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

// TechniqueHit is one search_technique result.
type TechniqueHit struct {
	Title   string `json:"title"`
	Path    string `json:"path"`
	Chunk   int    `json:"chunk"`
	Snippet string `json:"snippet"`
	Source  string `json:"source"`
}

// CVEInfo is the lookup_cve result.
type CVEInfo struct {
	ID          string       `json:"id"`
	Description string       `json:"description"`
	CVSS        *CVSS        `json:"cvss,omitempty"`
	CWEs        []string     `json:"cwes,omitempty"`
	References  []string     `json:"references,omitempty"`
	Exploits    []ExploitRef `json:"exploits,omitempty"`
	Source      string       `json:"source"`
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
	Source      string   `json:"source"`
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
		out = append(out, TechniqueHit{
			Title:   r.title.String,
			Path:    r.sourcePath.String,
			Chunk:   r.chunkIndex,
			Snippet: snippet(r.body, query, 300),
			Source:  source(r.packID, r.sourcePath.String, r.chunkIndex),
		})
	}
	return out, nil
}

// LookupCVE returns one CVE's structured record and the exploits that reference
// it. ok is false when the CVE is not in the active pack.
func (s *Store) LookupCVE(ctx context.Context, cve string) (CVEInfo, bool, error) {
	cve = strings.ToUpper(strings.TrimSpace(cve))
	if !cveRe.MatchString(cve) {
		return CVEInfo{}, false, fmt.Errorf("%q is not a CVE id", cve)
	}
	var packID string
	var title sql.NullString
	var metaRaw []byte
	err := s.db.QueryRowContext(ctx, `
SELECT p.pack_id, d.title, d.meta
FROM kb_documents d
JOIN kb_packs p ON p.id = d.pack_id AND p.active
WHERE d.kind='cve' AND lower(d.ext_id)=lower($1)
LIMIT 1`, cve).Scan(&packID, &title, &metaRaw)
	if err == sql.ErrNoRows {
		return CVEInfo{}, false, nil
	}
	if err != nil {
		return CVEInfo{}, false, err
	}
	var meta docMeta
	_ = json.Unmarshal(metaRaw, &meta)
	info := CVEInfo{
		ID:          cve,
		Description: title.String,
		CVSS:        meta.CVSS,
		CWEs:        meta.CWEs,
		References:  meta.References,
		Source:      source(packID, "nvd/"+cve, 0),
	}
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
	return info, true, exRows.Err()
}

// LookupSoftware resolves a product (and optional vendor and version) to the
// CVEs whose CPE applicability matches. Candidate rows are filtered by
// product/vendor in SQL, then the version range is evaluated in Go
// (CPEMatch.MatchesVersion), which the SQL cannot express for the odd CPE
// version strings. Results are one per CVE, highest CVSS first.
func (s *Store) LookupSoftware(ctx context.Context, product, vendor, version string, limit int) ([]SoftwareHit, error) {
	product = strings.ToLower(strings.TrimSpace(product))
	vendor = strings.ToLower(strings.TrimSpace(vendor))
	if product == "" {
		return nil, fmt.Errorf("a product name is required")
	}
	limit = clampLimit(limit, 50)
	// Normalise a human product ("Apache httpd") toward CPE form ("http_server"
	// won't match, but "httpd"/"apache" will via trigram); match exact or fuzzy.
	rows, err := s.db.QueryContext(ctx, `
SELECT p.pack_id, d.ext_id, d.title, d.meta, m.criteria,
       m.version_start_including, m.version_start_excluding,
       m.version_end_including, m.version_end_excluding
FROM kb_cpe_matches m
JOIN kb_documents d ON d.id = m.document_id
JOIN kb_packs p ON p.id = d.pack_id AND p.active
WHERE m.vulnerable
  AND (m.product = $1 OR m.product ILIKE '%'||$1||'%')
  AND ($2 = '' OR m.vendor = $2)
LIMIT 5000`, product, vendor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type cand struct {
		hit  SoftwareHit
		rank float64
	}
	best := map[string]cand{}
	for rows.Next() {
		var packID string
		var extID, title sql.NullString
		var metaRaw []byte
		var m CPEMatch
		if err := rows.Scan(&packID, &extID, &title, &metaRaw, &m.Criteria,
			&m.VersionStartIncluding, &m.VersionStartExcluding,
			&m.VersionEndIncluding, &m.VersionEndExcluding); err != nil {
			return nil, err
		}
		if version != "" && !m.MatchesVersion(version) {
			continue
		}
		var meta docMeta
		_ = json.Unmarshal(metaRaw, &meta)
		cve := extID.String
		score := 0.0
		if meta.CVSS != nil {
			score = meta.CVSS.BaseScore
		}
		if cur, ok := best[cve]; ok && cur.rank >= score {
			continue
		}
		best[cve] = cand{rank: score, hit: SoftwareHit{
			CVE: cve, Description: title.String, CVSS: meta.CVSS, CWEs: meta.CWEs,
			MatchedCPE: m.Criteria, Source: source(packID, "nvd/"+cve, 0),
		}}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]SoftwareHit, 0, len(best))
	for _, c := range best {
		out = append(out, c.hit)
	}
	sortByCVSS(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
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
	if len(body) > s.cfg.MaxChunkBytes {
		body = body[:s.cfg.MaxChunkBytes]
	}
	return KnowledgeChunk{
		Title: title.String, Path: sourcePath.String, Chunk: chunk, TotalChunks: total,
		Text: body, Source: source(packID, sourcePath.String, chunk),
	}, true, nil
}

// DocumentFilePath returns the on-disk path of a document's source file, for
// copy_knowledge_file: the pack directory joined with the document's source
// path, re-checked to stay within the pack directory. ok is false when the
// document has no file (a CVE) or is not found.
func (s *Store) DocumentFilePath(ctx context.Context, ref string) (absPath, packID, sourcePath string, ok bool, err error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", "", "", false, fmt.Errorf("a document id or source path is required")
	}
	var sp sql.NullString
	err = s.db.QueryRowContext(ctx, `
SELECT p.pack_id, d.source_path
FROM kb_documents d
JOIN kb_packs p ON p.id = d.pack_id AND p.active
WHERE (d.source_path = $1 OR lower(d.ext_id) = lower($1)) AND d.source_path IS NOT NULL
LIMIT 1`, ref).Scan(&packID, &sp)
	if err == sql.ErrNoRows {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, err
	}
	clean, perr := SafePath(sp.String)
	if perr != nil {
		return "", "", "", false, perr
	}
	return s.cfg.PackDir(packID) + "/" + clean, packID, clean, true, nil
}
