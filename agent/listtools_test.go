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
	"github.com/doracpphp/artex-offline/offline"
)

func writeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

type listToolsOut struct {
	Count   int         `json:"count"`
	Tools   []toolEntry `json:"tools"`
	Missing []string    `json:"missing"`
}

func callListTools(t *testing.T, input string) listToolsOut {
	t.Helper()
	res, err := NewToolSet(nil, "").listTools().Call(context.Background(), json.RawMessage(input), nil)
	if err != nil || res.IsError {
		t.Fatalf("list_tools: %v %s", err, res.Flatten())
	}
	var out listToolsOut
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("decode %q: %v", res.Flatten(), err)
	}
	return out
}

// TestListToolsInventory: the image inventory and a toolbox manifest are
// merged; tools are located on disk (never run), a listed but absent tool is
// reported as missing, and a toolbox built for another base image is flagged.
func TestListToolsInventory(t *testing.T) {
	dir := t.TempDir()
	nuclei := filepath.Join(dir, "bin", "nuclei")
	writeFile(t, nuclei, "#!/bin/sh\nexit 99\n", 0o755)
	inv := filepath.Join(dir, "tool-inventory.json")
	writeFile(t, inv, `{"base_version":"v2.0.0","tools":[
		{"name":"nuclei","version":"v3.11.1","path":"`+filepath.ToSlash(nuclei)+`"},
		{"name":"ghost-tool","version":"1.0","path":"/nonexistent/ghost-tool"}]}`, 0o644)
	box := filepath.Join(dir, "toolbox")
	writeFile(t, filepath.Join(box, "web", "bin", "wfuzz"), "#!/bin/sh\n", 0o755)
	writeFile(t, filepath.Join(box, "web", "manifest.json"), `{"category":"web","base_version":"v1.9.0","tools":[{"name":"wfuzz","version":"3.1.0"}]}`, 0o644)
	writeFile(t, filepath.Join(box, "broken", "manifest.json"), `not json`, 0o644)
	t.Setenv(toolInventoryEnv, inv)
	t.Setenv(toolboxDirEnv, box)

	out := callListTools(t, `{}`)
	if out.Count != 2 {
		t.Fatalf("want nuclei and wfuzz, got %+v", out.Tools)
	}
	byName := map[string]toolEntry{}
	for _, e := range out.Tools {
		byName[e.Name] = e
	}
	n := byName["nuclei"]
	if n.Source != "image" || n.Version != "v3.11.1" || !strings.Contains(strings.Join(n.Tags, ","), "web") {
		t.Errorf("nuclei: %+v (want image source, version and known tags)", n)
	}
	w := byName["wfuzz"]
	if w.Source != "toolbox:web" || !strings.HasSuffix(filepath.ToSlash(w.Path), "toolbox/web/bin/wfuzz") {
		t.Errorf("wfuzz: %+v (want toolbox source and its bin path)", w)
	}
	if !strings.Contains(w.Note, "v1.9.0") || !strings.Contains(w.Note, "v2.0.0") {
		t.Errorf("a toolbox built for another base image must be flagged, note %q", w.Note)
	}
	if len(out.Missing) != 1 || out.Missing[0] != "ghost-tool" {
		t.Errorf("missing = %v, want [ghost-tool]", out.Missing)
	}

	if got := callListTools(t, `{"tag":"web"}`); got.Count != 2 {
		t.Errorf("tag web: %+v", got.Tools)
	}
	if got := callListTools(t, `{"search":"fuz"}`); got.Count != 1 || got.Tools[0].Name != "wfuzz" {
		t.Errorf("search fuz: %+v", got.Tools)
	}
	if got := callListTools(t, `{"tag":"ad"}`); got.Count != 0 {
		t.Errorf("tag ad: %+v", got.Tools)
	}
}

// TestListToolsPathFallback: without a build-time inventory, the well-known
// tools found on PATH are listed.
func TestListToolsPathFallback(t *testing.T) {
	dir := t.TempDir()
	name := "nmap"
	if filepath.Separator == '\\' {
		name = "nmap.exe" // exec.LookPath needs an executable extension on Windows
	}
	writeFile(t, filepath.Join(dir, name), "#!/bin/sh\n", 0o755)
	t.Setenv("PATH", dir)
	t.Setenv(toolInventoryEnv, filepath.Join(dir, "absent.json"))
	t.Setenv(toolboxDirEnv, filepath.Join(dir, "no-toolbox"))
	out := callListTools(t, `{}`)
	if out.Count != 1 || out.Tools[0].Name != "nmap" || out.Tools[0].Source != "path" {
		t.Fatalf("want nmap from PATH, got %+v", out.Tools)
	}
}

func TestOfflinePromptBlock(t *testing.T) {
	t.Setenv(offline.Env, "1")
	for name, prompt := range map[string]string{
		"planner":   plannerSystem("g", t.TempDir(), t.TempDir()),
		"worker":    workerSystem("", "", t.TempDir(), t.TempDir()),
		"mainagent": mainAgentSystem("g", t.TempDir(), t.TempDir()),
		"chat":      chatSystem("assistant", t.TempDir(), t.TempDir()),
	} {
		if !strings.Contains(prompt, "[Offline mode.") || !strings.Contains(prompt, "list_tools") {
			t.Errorf("%s: the offline block is missing", name)
		}
	}
	t.Setenv(offline.Env, "0")
	if strings.Contains(plannerSystem("g", t.TempDir(), t.TempDir()), "[Offline mode.") {
		t.Error("the offline block must not appear when offline mode is off")
	}
}

func TestListToolsBoundAndKept(t *testing.T) {
	ts := NewToolSet(nil, "")
	for name, tools := range map[string][]actool.CoreTool{
		"planner": ts.PlannerTools(), "worker": ts.WorkerTools(), "mainagent": ts.MainAgentTools(),
	} {
		if !slices.ContainsFunc(tools, func(c actool.CoreTool) bool { return c.Name() == "list_tools" }) {
			t.Errorf("%s must have list_tools", name)
		}
	}
	if !toolRAGCore["list_tools"] {
		t.Error("Tool RAG must never project list_tools away")
	}
}
