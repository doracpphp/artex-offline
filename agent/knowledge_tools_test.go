package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/doracpphp/artex-offline/knowledge"
)

// fakeKnowledge is a KnowledgeStore double for the tool tests.
type fakeKnowledge struct {
	exploits  []knowledge.ExploitHit
	technique []knowledge.TechniqueHit
	cve       knowledge.CVEInfo
	cveOK     bool
	software  []knowledge.SoftwareHit
	chunk     knowledge.KnowledgeChunk
	chunkOK   bool
	filePath  string
	fileSrc   string
	fileOK    bool
	lastQuery string
}

func (f *fakeKnowledge) SearchExploits(_ context.Context, q, typ, plat string, _ int) ([]knowledge.ExploitHit, error) {
	f.lastQuery = q + "|" + typ + "|" + plat
	return f.exploits, nil
}
func (f *fakeKnowledge) SearchTechnique(_ context.Context, q string, _ int) ([]knowledge.TechniqueHit, error) {
	f.lastQuery = q
	return f.technique, nil
}
func (f *fakeKnowledge) LookupCVE(_ context.Context, cve string) (knowledge.CVEInfo, bool, error) {
	return f.cve, f.cveOK, nil
}
func (f *fakeKnowledge) LookupSoftware(_ context.Context, p, v, ver string, _ int) ([]knowledge.SoftwareHit, error) {
	return f.software, nil
}
func (f *fakeKnowledge) ReadKnowledge(_ context.Context, ref string, chunk int) (knowledge.KnowledgeChunk, bool, error) {
	return f.chunk, f.chunkOK, nil
}
func (f *fakeKnowledge) ReadDocumentFile(_ context.Context, ref string, maxBytes int64) ([]byte, string, string, bool, error) {
	if !f.fileOK {
		return nil, "", "", false, nil
	}
	data, err := os.ReadFile(f.filePath)
	if err != nil {
		return nil, "", "", false, err
	}
	return data, "artex-core", f.fileSrc, true, nil
}

func callTool(t *testing.T, tool actool.CoreTool, input string) actool.Result {
	t.Helper()
	res, err := tool.Call(context.Background(), json.RawMessage(input), nil)
	if err != nil {
		t.Fatalf("%s: %v", tool.Name(), err)
	}
	return res
}

func TestKnowledgeQueryTools(t *testing.T) {
	fk := &fakeKnowledge{
		exploits: []knowledge.ExploitHit{{EDBID: "42", Title: "Apache RCE", Source: "artex-core:exploitdb/42.c"}},
		cve:      knowledge.CVEInfo{ID: "CVE-2021-41773", Description: "path traversal"},
		cveOK:    true,
		software: []knowledge.SoftwareHit{{CVE: "CVE-2021-41773", MatchedCPE: "cpe:2.3:a:apache:http_server:2.4.49"}},
	}
	ts := NewToolSet(nil, "")
	ts.SetKnowledge(fk)
	tools := map[string]actool.CoreTool{}
	for _, tool := range ts.knowledgeQueryTools() {
		tools[tool.Name()] = tool
	}

	res := callTool(t, tools["search_exploits"], `{"query":"apache","type":"remote","platform":"linux"}`)
	if res.IsError || !strings.Contains(res.Flatten(), "42") {
		t.Fatalf("search_exploits: %s", res.Flatten())
	}
	if fk.lastQuery != "apache|remote|linux" {
		t.Errorf("filters not passed through: %q", fk.lastQuery)
	}
	if res := callTool(t, tools["search_exploits"], `{"query":"  "}`); !res.IsError {
		t.Error("empty query should error")
	}

	res = callTool(t, tools["lookup_cve"], `{"cve":"CVE-2021-41773"}`)
	if res.IsError || !strings.Contains(res.Flatten(), "path traversal") {
		t.Fatalf("lookup_cve: %s", res.Flatten())
	}
	fk.cveOK = false
	if res := callTool(t, tools["lookup_cve"], `{"cve":"CVE-2000-0001"}`); !strings.Contains(res.Flatten(), "false") {
		t.Errorf("absent CVE should report found=false: %s", res.Flatten())
	}

	res = callTool(t, tools["lookup_software"], `{"product":"http_server","vendor":"apache","version":"2.4.49"}`)
	if res.IsError || !strings.Contains(res.Flatten(), "CVE-2021-41773") {
		t.Fatalf("lookup_software: %s", res.Flatten())
	}
	if res := callTool(t, tools["lookup_software"], `{"product":""}`); !res.IsError {
		t.Error("missing product should error")
	}
}

func TestKnowledgeToolsUnavailable(t *testing.T) {
	ts := NewToolSet(nil, "") // no store set
	for _, tool := range ts.knowledgeQueryTools() {
		res := callTool(t, tool, `{"query":"x","cve":"CVE-2021-1","product":"x","ref":"x"}`)
		if !res.IsError || !strings.Contains(res.Flatten(), "no knowledge pack") {
			t.Errorf("%s without a store should report no pack: %s", tool.Name(), res.Flatten())
		}
	}
}

func TestCopyKnowledgeFile(t *testing.T) {
	base := t.TempDir()
	runDir := filepath.Join(base, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The source "pack" file lives outside the run directory.
	packFile := filepath.Join(base, "pack", "exploit.c")
	os.MkdirAll(filepath.Dir(packFile), 0o755)
	os.WriteFile(packFile, []byte("int main(){}\n"), 0o644)

	fk := &fakeKnowledge{filePath: packFile, fileSrc: "exploitdb/exploits/42.c", fileOK: true}
	ts := NewToolSet(nil, "")
	ts.SetKnowledge(fk)
	ts.SetWorkBase(base)
	tool := ts.copyKnowledgeFile()

	res, err := tool.Call(context.Background(), json.RawMessage(`{"ref":"42"}`), &actool.ToolContext{WorkingDir: runDir})
	if err != nil || res.IsError {
		t.Fatalf("copy_knowledge_file: %v %s", err, res.Flatten())
	}
	// Default name is the source base name; it must land in the run directory.
	got, err := os.ReadFile(filepath.Join(runDir, "42.c"))
	if err != nil || string(got) != "int main(){}\n" {
		t.Fatalf("copied file: %q err %v", got, err)
	}
	// A CVE (no file) reports a helpful error.
	fk.fileOK = false
	if res := callTool(t, tool, `{"ref":"CVE-2021-1"}`); !res.IsError {
		t.Error("a ref with no file should error")
	}
}

func TestKnowledgeToolsBoundAndKept(t *testing.T) {
	ts := NewToolSet(nil, "")
	planner := toolNames(ts.PlannerTools())
	worker := toolNames(ts.WorkerTools())
	for _, n := range []string{"search_exploits", "lookup_cve", "lookup_software", "search_technique", "read_knowledge"} {
		if !slices.Contains(planner, n) {
			t.Errorf("planner missing %s", n)
		}
		if !slices.Contains(worker, n) {
			t.Errorf("worker missing %s", n)
		}
		if !toolRAGCore[n] {
			t.Errorf("%s must be in toolRAGCore", n)
		}
	}
	if slices.Contains(planner, "copy_knowledge_file") {
		t.Error("copy_knowledge_file must not be a planner tool")
	}
	if !slices.Contains(worker, "copy_knowledge_file") {
		t.Error("worker must have copy_knowledge_file")
	}
}

// toolNames returns the tool names of a list (shadows the dir-entry helper used in
// other tests, scoped here to CoreTool).
func toolNames(tools []actool.CoreTool) []string {
	out := make([]string, len(tools))
	for i, t := range tools {
		out[i] = t.Name()
	}
	return out
}
