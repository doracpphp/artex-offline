package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/doracpphp/artex-offline/agent"
	"github.com/doracpphp/artex-offline/knowledge"
)

// Offline knowledge search wiring (docs/offline-knowledge-search.md). The store
// indexes imported packs; the agent provider lets each run's ToolSet reach it,
// and a cached availability flag lets ToolResolve drop the tools when no pack is
// active. Import is operator-driven, through POST /api/knowledge/import (there
// is no UI for it yet).

// knowledgeAvailable caches whether a pack is active, so ToolResolve (run on
// every agent build) does not query the DB each time. It is refreshed at init
// and after every import.
var knowledgeActive atomic.Bool

// initKnowledge builds the knowledge store and installs the agent provider. It
// is a no-op without a database. When knowledge is disabled it leaves the
// provider unset, so the tools are dropped from every agent.
func (s *Server) initKnowledge(dataDir string) {
	if s.m == nil || s.m.pg == nil {
		return
	}
	cfg := knowledge.LoadConfig(dataDir)
	if !cfg.Enabled {
		log.Printf("[knowledge] disabled (%s=0): search_* / lookup_* tools are not offered", knowledge.EnabledEnv)
		return
	}
	store := knowledge.NewStore(s.m.pg.DB, cfg)
	// Trigram indexes speed up the ILIKE fallback; best effort (no rights, or a
	// Postgres without contrib, only makes that fallback slower).
	if err := store.EnsureTrigramIndexes(s.ctx); err != nil {
		log.Printf("[knowledge] pg_trgm unavailable (%v): identifier and partial-name search use sequential scans", err)
	}
	if keys, err := knowledge.TrustedKeyList(); err != nil {
		log.Printf("[knowledge] signing keys: %v (imports are refused until this is fixed)", err)
	} else {
		for _, k := range keys {
			log.Printf("[knowledge] trusted signing key %s (%s): sha256 %s", k.KeyID, k.Source, k.Fingerprint)
		}
	}
	// Optional local embedding model for hybrid (lexical + vector) search. Without
	// one, or without pgvector, search is lexical-only. An invalid endpoint (e.g.
	// a cloud host in offline mode) is logged and the feature stays lexical.
	embedder, err := knowledge.NewEmbedderFromEnv()
	if err != nil {
		log.Printf("[knowledge] embedding disabled: %v (search is lexical-only)", err)
	} else if embedder != nil {
		store.SetEmbedder(embedder)
	}
	s.knowledge = store
	knowledgeActive.Store(store.HasActivePack(s.ctx))
	agent.SetKnowledgeProvider(
		func() agent.KnowledgeStore { return store },
		knowledgeActive.Load,
	)
	if v, ok, _ := anyActivePack(s.ctx, store); ok {
		log.Printf("[knowledge] active pack indexed (%s); search_exploits / lookup_cve / lookup_software / search_technique / read_knowledge / copy_knowledge_file are available", v)
		if embedder != nil {
			// Build/resume the vector index for the already-active pack (e.g. after a
			// restart, or a pack imported before the embedder was configured).
			store.EmbedActivePackAsync()
		}
	} else {
		log.Printf("[knowledge] enabled; no pack imported yet (import one with POST /api/knowledge/import, see docs/offline-knowledge-search.md)")
	}
	if embedder != nil {
		cfg, _ := knowledge.LoadEmbedConfig()
		log.Printf("[knowledge] hybrid search: embedding model %q at %s (vector index builds in the background when pgvector is available)", cfg.Model, cfg.Endpoint)
	}
}

// anyActivePack reports the version of some active pack (packs share one id in
// Phase 1, so this is the active pack's version), for the startup log.
func anyActivePack(ctx context.Context, store *knowledge.Store) (string, bool, error) {
	packs, err := store.ListPacks(ctx)
	if err != nil {
		return "", false, err
	}
	for _, p := range packs {
		if p.Active {
			return p.PackID + " " + p.Version, true, nil
		}
	}
	return "", false, nil
}

// maxKnowledgePackBytes caps a streamed pack upload. Packs can be several GB
// (docs §5); this is a generous ceiling against an accidental huge upload.
const maxKnowledgePackBytes = 12 << 30

// listKnowledgePacks: GET /api/knowledge/packs → the imported packs (each with
// the fingerprint of the key that verified it), the per-pack-id key pins, and
// the trusted signing keys with their fingerprints, so an operator can compare
// them out of band.
func (s *Server) listKnowledgePacks(w http.ResponseWriter, r *http.Request) {
	if s.knowledge == nil {
		writeJSON(w, 200, map[string]any{"enabled": false, "packs": []any{}})
		return
	}
	packs, err := s.knowledge.ListPacks(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	pins, err := s.knowledge.KeyPins(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := map[string]any{"enabled": true, "active": knowledgeActive.Load(), "packs": packs, "key_pins": pins}
	if keys, err := knowledge.TrustedKeyList(); err != nil {
		out["trusted_keys_error"] = err.Error()
	} else {
		out["trusted_keys"] = keys
	}
	writeJSON(w, 200, out)
}

// importKnowledgePack: POST /api/knowledge/import imports a signed pack and
// activates it. Two forms:
//   - a server-side file: ?path=<path> (or JSON {"path":...}); the file must be
//     under the data directory (e.g. the knowledge inbox), so the API cannot be
//     used to read an arbitrary server file as a "pack".
//   - a streamed upload: the request body is the pack bytes (Content-Type
//     application/gzip or octet-stream); it is written to the inbox and imported.
//
// ?allow_downgrade=1 permits importing a version older than the active one.
// ?repin=1 accepts a pack signed by a key other than the one its pack id was
// pinned to at first import (an intended key rotation), and pins the new key.
//
// The import runs synchronously (up to 30 minutes for a multi-GB pack); a
// second import while one runs is refused with 409.
func (s *Server) importKnowledgePack(w http.ResponseWriter, r *http.Request) {
	if s.knowledge == nil {
		writeErr(w, 400, "knowledge search is disabled ("+knowledge.EnabledEnv+"=0)")
		return
	}
	keys, err := knowledge.TrustedKeys()
	if err != nil {
		writeErr(w, 400, "knowledge signing keys: "+err.Error())
		return
	}
	opt := knowledge.ImportOptions{
		AllowDowngrade: truthy(r.URL.Query().Get("allow_downgrade")),
		Repin:          truthy(r.URL.Query().Get("repin")),
		// nuclei-templates baked into the image, for the version check (docs §5).
		ImageTemplatesVersion: agent.InstalledToolVersion("nuclei-templates"),
	}
	cfg := s.knowledge.Config()
	inbox := filepath.Join(cfg.Dir, "inbox")

	var packPath string
	var cleanup func()
	if p := r.URL.Query().Get("path"); p != "" {
		resolved, err := resolveServerPackPath(cfg.Dir, p)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		packPath = resolved
	} else {
		// Streamed upload to the inbox.
		if err := os.MkdirAll(inbox, 0o755); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		tmp, err := os.CreateTemp(inbox, "upload-*.tar.gz")
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		packPath = tmp.Name()
		cleanup = func() { os.Remove(packPath) }
		n, err := io.Copy(tmp, io.LimitReader(http.MaxBytesReader(w, r.Body, maxKnowledgePackBytes), maxKnowledgePackBytes))
		cerr := tmp.Close()
		if err != nil {
			cleanup()
			writeErr(w, 400, "read upload: "+err.Error())
			return
		}
		if cerr != nil {
			cleanup()
			writeErr(w, 500, cerr.Error())
			return
		}
		if n == 0 {
			cleanup()
			writeErr(w, 400, "empty upload; POST the pack .tar.gz as the request body, or pass ?path=")
			return
		}
	}
	if cleanup != nil {
		defer cleanup()
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Minute)
	defer cancel()
	res, err := s.knowledge.Import(ctx, packPath, keys, opt)
	if errors.Is(err, knowledge.ErrImportBusy) {
		writeErr(w, 409, err.Error())
		return
	}
	if err != nil {
		writeErr(w, 400, "import failed: "+err.Error())
		return
	}
	knowledgeActive.Store(true)
	kind := "full pack"
	if res.BaseVersion != "" {
		kind = "delta from " + res.BaseVersion
	}
	log.Printf("[knowledge] imported pack %s %s (%s; key %s, sha256 %s): %d exploits, %d CVEs, %d docs, %d templates (%d skipped), %d vectors reused",
		res.PackID, res.Version, kind, res.KeyID, res.KeyFingerprint, res.Exploits, res.CVEs, res.Docs, res.Templates, res.Skipped, res.Carried)
	for _, w := range res.Warnings {
		log.Printf("[knowledge] WARNING: %s", w)
	}
	writeJSON(w, 200, res)
}

// resolveServerPackPath resolves a ?path= pack location and requires it to be
// under the knowledge directory, so the import API cannot open an arbitrary
// server file. An absolute path is accepted only when it is within knowledgeDir.
func resolveServerPackPath(knowledgeDir, p string) (string, error) {
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(knowledgeDir, p)
	}
	abs = filepath.Clean(abs)
	base := filepath.Clean(knowledgeDir)
	rel, err := filepath.Rel(base, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path must be inside the knowledge directory %s (place the pack in %s)", base, filepath.Join(base, "inbox"))
	}
	if fi, err := os.Stat(abs); err != nil || fi.IsDir() {
		return "", fmt.Errorf("pack file not found at %s", abs)
	}
	return abs, nil
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}
