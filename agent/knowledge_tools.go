package agent

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"

	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/doracpphp/artex-offline/knowledge"
)

// Offline knowledge-search tools (docs/offline-knowledge-search.md §4.3). They
// give the agent, as tools, the local substitute for the web search offline mode
// refuses: exploit and technique search, CVE and software lookup, and a way to
// pull an exploit file into the run's working directory to use it. Every result
// carries a source citation the model copies into a finding's evidence.
//
// The store is optional: a ToolSet without one (SetKnowledge not called, or
// knowledge disabled, or no pack imported) makes each tool return a clear
// message instead of failing. The server also drops these tools from an agent's
// catalog when no pack is active (SetKnowledgeAvailable), so in practice the
// message is only seen in a misconfiguration.

// KnowledgeStore is the subset of *knowledge.Store the tools use, so tests can
// substitute a fake and the agent package does not hard-depend on the DB.
type KnowledgeStore interface {
	SearchExploits(ctx context.Context, query, typ, platform string, limit int) ([]knowledge.ExploitHit, error)
	SearchTechnique(ctx context.Context, query string, limit int) ([]knowledge.TechniqueHit, error)
	LookupCVE(ctx context.Context, cve string) (knowledge.CVEInfo, bool, error)
	LookupSoftware(ctx context.Context, product, vendor, version string, limit int) ([]knowledge.SoftwareHit, error)
	ReadKnowledge(ctx context.Context, ref string, chunk int) (knowledge.KnowledgeChunk, bool, error)
	ReadDocumentFile(ctx context.Context, ref string, maxBytes int64) (data []byte, packID, sourcePath string, ok bool, err error)
}

// SetKnowledge wires the knowledge store into this ToolSet. nil (the default)
// leaves the knowledge tools returning "not available".
func (t *ToolSet) SetKnowledge(k KnowledgeStore) { t.knowledge = k }

// KnowledgeToolNames are the knowledge-search tools, so the server can drop them
// from an agent's catalog when no pack is active (ToolResolve).
var KnowledgeToolNames = []string{
	"search_exploits", "lookup_cve", "lookup_software", "search_technique",
	"read_knowledge", "copy_knowledge_file",
}

// knowledgeProvider supplies the knowledge store to each run's ToolSet. The
// server installs it once the store is built; nil (the default) means no store,
// so the tools report "not available" if they are reached.
var knowledgeProvider func() KnowledgeStore

// knowledgeAvailable reports whether knowledge search is usable (enabled and a
// pack is active). The server installs it; ToolResolve drops the knowledge tools
// when it is false, so they never clutter an agent that has nothing to search.
var knowledgeAvailable func() bool

// SetKnowledgeProvider installs (or clears with nil) the knowledge store
// provider and the availability predicate. available may be nil, which means
// "always available when a provider is set".
func SetKnowledgeProvider(provider func() KnowledgeStore, available func() bool) {
	knowledgeProvider = provider
	knowledgeAvailable = available
}

// KnowledgeAvailable reports the current availability (true when no predicate is
// installed but a provider is). Used by the server's ToolResolve.
func KnowledgeAvailable() bool {
	if knowledgeAvailable != nil {
		return knowledgeAvailable()
	}
	return knowledgeProvider != nil
}

// applyKnowledge sets the provider's store on tsx, if one is installed. Called
// from each run's ToolSet construction (worker, planner).
func (t *ToolSet) ApplyKnowledge() {
	if knowledgeProvider != nil {
		if k := knowledgeProvider(); k != nil {
			t.knowledge = k
		}
	}
}

// KnowledgeTools returns the knowledge-search tools bound to planner and worker.
// read_knowledge and the search/lookup tools serve both; copy_knowledge_file is
// worker-only (it needs the run's shell/file tools) and is added in WorkerTools.
func (t *ToolSet) knowledgeQueryTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.searchExploits(), t.lookupCVE(), t.lookupSoftware(), t.searchTechnique(), t.readKnowledge(),
	}
}

func (t *ToolSet) knowledgeUnavailable() actool.Result {
	return actool.Errorf("knowledge search is not available: no knowledge pack is imported (an operator imports one under System → Knowledge). Do not try to reach the internet; work with the tools listed by list_tools.")
}

func (t *ToolSet) searchExploits() actool.CoreTool {
	return readTool(
		"search_exploits",
		"Search the local ExploitDB mirror for exploits by keyword, CVE, type or platform. "+
			"Returns matching entries (EDB-ID, title, type, platform, date, verified, linked CVEs, file path) with a source citation. "+
			"Use copy_knowledge_file to bring an exploit file into your working directory. Offline substitute for web search.",
		obj(map[string]any{
			"query":    str("keywords, a product name, or a CVE id"),
			"type":     str("optional filter: remote | local | webapps | dos | shellcode"),
			"platform": str("optional filter: linux | windows | php | multiple | ..."),
		}, "query"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.knowledge == nil {
				return t.knowledgeUnavailable(), nil
			}
			var a struct {
				Query, Type, Platform string
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Query) == "" {
				return actool.Errorf("query is required"), nil
			}
			hits, err := t.knowledge.SearchExploits(ctx, a.Query, a.Type, a.Platform, 0)
			if err != nil {
				return actool.Errorf("search_exploits failed: " + err.Error()), nil
			}
			return jsonResult(map[string]any{"count": len(hits), "exploits": hits})
		},
	)
}

func (t *ToolSet) searchTechnique() actool.CoreTool {
	return readTool(
		"search_technique",
		"Search the local technique documentation (PayloadsAllTheThings, HackTricks, WSTG, etc.) for how to do something: "+
			"an attack technique, a payload, a WAF-evasion trick. Returns passages with their source path and a citation; "+
			"use read_knowledge to get a passage's full text. Offline substitute for web search.",
		obj(map[string]any{
			"query": str("what you want to do, in keywords (e.g. 'bypass WAF union select', 'JWT none algorithm')"),
		}, "query"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.knowledge == nil {
				return t.knowledgeUnavailable(), nil
			}
			var a struct{ Query string }
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Query) == "" {
				return actool.Errorf("query is required"), nil
			}
			hits, err := t.knowledge.SearchTechnique(ctx, a.Query, 0)
			if err != nil {
				return actool.Errorf("search_technique failed: " + err.Error()), nil
			}
			return jsonResult(map[string]any{"count": len(hits), "passages": hits})
		},
	)
}

func (t *ToolSet) lookupCVE() actool.CoreTool {
	return readTool(
		"lookup_cve",
		"Look up a CVE in the local NVD mirror: description, CVSS score, CWE, references, and the ExploitDB entries that reference it. "+
			"Offline substitute for searching the web for a CVE.",
		obj(map[string]any{
			"cve": str("a CVE id, e.g. CVE-2021-41773"),
		}, "cve"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.knowledge == nil {
				return t.knowledgeUnavailable(), nil
			}
			var a struct{ CVE string }
			_ = json.Unmarshal(in, &a)
			info, ok, err := t.knowledge.LookupCVE(ctx, a.CVE)
			if err != nil {
				return actool.Errorf("lookup_cve: " + err.Error()), nil
			}
			if !ok {
				return jsonResult(map[string]any{"found": false, "cve": strings.ToUpper(strings.TrimSpace(a.CVE))})
			}
			return jsonResult(map[string]any{"found": true, "cve": info})
		},
	)
}

func (t *ToolSet) lookupSoftware() actool.CoreTool {
	return readTool(
		"lookup_software",
		"Find the CVEs affecting a product and version from the local NVD mirror, via CPE matching (handles version ranges). "+
			"Give the product a fingerprint revealed (e.g. 'http_server' or 'wordpress') and optionally the vendor and version. "+
			"Returns CVEs with CVSS and the matched CPE, most severe first. Offline substitute for a web vulnerability lookup.",
		obj(map[string]any{
			"product": str("product name as it appears in CPE, e.g. http_server, openssl, wordpress"),
			"vendor":  str("optional vendor, e.g. apache, openbsd"),
			"version": str("optional version, e.g. 2.4.49; omit to list all CVEs for the product"),
		}, "product"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.knowledge == nil {
				return t.knowledgeUnavailable(), nil
			}
			var a struct {
				Product, Vendor, Version string
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Product) == "" {
				return actool.Errorf("product is required"), nil
			}
			hits, err := t.knowledge.LookupSoftware(ctx, a.Product, a.Vendor, a.Version, 0)
			if err != nil {
				return actool.Errorf("lookup_software: " + err.Error()), nil
			}
			return jsonResult(map[string]any{"count": len(hits), "cves": hits})
		},
	)
}

func (t *ToolSet) readKnowledge() actool.CoreTool {
	return readTool(
		"read_knowledge",
		"Read the full text of one passage returned by search_exploits or search_technique, by its document id or source path plus chunk number. "+
			"Progressive disclosure: search first, then read the passage you need.",
		obj(map[string]any{
			"ref":   str("the source path or id from a search result, e.g. docs/sqli.md or an EDB-ID"),
			"chunk": map[string]any{"type": "integer", "description": "1-based passage number (default 1)"},
		}, "ref"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.knowledge == nil {
				return t.knowledgeUnavailable(), nil
			}
			var a struct {
				Ref   string
				Chunk int
			}
			_ = json.Unmarshal(in, &a)
			kc, ok, err := t.knowledge.ReadKnowledge(ctx, a.Ref, a.Chunk)
			if err != nil {
				return actool.Errorf("read_knowledge: " + err.Error()), nil
			}
			if !ok {
				return actool.Errorf("no passage found for ref " + a.Ref), nil
			}
			return jsonResult(kc)
		},
	)
}

// copyKnowledgeFile copies an exploit (or template) file from the active pack
// into the run's working directory, where Bash and the file tools can use it. It
// is worker-only. The pack files are server-owned; the copy crosses that
// boundary deliberately and lands inside the run directory (os.Root-confined).
func (t *ToolSet) copyKnowledgeFile() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "copy_knowledge_file",
		Description: "Copy a file from the knowledge pack (an exploit source, a template) into your working directory so you can read, adapt and run it. " +
			"Give the source path or id from search_exploits. The destination is inside your working directory; it is created there. " +
			"Returns the local path. Running a copied exploit still goes through the normal approvals.",
		Schema: obj(map[string]any{
			"ref":  str("the exploit file path or EDB-ID from a search result"),
			"name": str("optional destination file name in your working directory (default: the source's base name)"),
		}, "ref"),
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			return t.runCopyKnowledgeFile(ctx, in, tc)
		},
	})
}

func (t *ToolSet) runCopyKnowledgeFile(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	if t.knowledge == nil {
		return t.knowledgeUnavailable(), nil
	}
	var a struct {
		Ref, Name string
	}
	if err := json.Unmarshal(in, &a); err != nil || strings.TrimSpace(a.Ref) == "" {
		return actool.Errorf("ref is required"), nil
	}
	// The store opens the file confined to the active pack's directory and caps
	// its size (knowledge.ReadDocumentFile); this tool runs with the server's
	// identity, so it never opens a path itself.
	data, _, sourcePath, ok, err := t.knowledge.ReadDocumentFile(ctx, a.Ref, knowledge.MaxDocumentFileBytes)
	if err != nil {
		return actool.Errorf("copy_knowledge_file: " + err.Error()), nil
	}
	if !ok {
		return actool.Errorf("no file found for ref " + a.Ref + " (a CVE has no file, and an exploit whose file is not in the pack has none either; use lookup_cve / read_knowledge)"), nil
	}
	dir := ""
	if tc != nil {
		dir = tc.WorkingDir
	}
	root, err := openWorkRoot(t.workBase, dir)
	if err != nil {
		return actool.Errorf("copy_knowledge_file: " + err.Error()), nil
	}
	defer root.Close()
	name := strings.TrimSpace(a.Name)
	if name == "" {
		name = filepath.Base(filepath.FromSlash(sourcePath))
	}
	relName, err := root.rel(name)
	if err != nil {
		return root.refuse(name), nil
	}
	if err := root.writeFile(relName, data); err != nil {
		return actool.Errorf("copy_knowledge_file: write: " + err.Error()), nil
	}
	return jsonResult(map[string]any{
		"copied": true, "source": sourcePath, "path": filepath.Join(root.dir, relName), "bytes": len(data),
	})
}
