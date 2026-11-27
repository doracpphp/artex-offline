package agent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// list_tools: the inventory of command-line tools the agent can run
// (docs/offline-toolbox.md §6.1). A model that does not know what is installed
// tries to download what it wants; offline that only burns turns. The list is
// read from manifests and the files are only checked for existence: no tool is
// executed to learn its version (that would be slow, and would run code as the
// server).
//
// Sources, in order:
//   - the build-time inventory the Dockerfile writes (ARTEX_TOOL_INVENTORY,
//     default tool-inventory.json next to the executable): pinned binaries,
//     the apt packages, bbot, Playwright, nuclei-templates;
//   - toolbox manifests under ARTEX_TOOLBOX_DIR (default /opt/toolbox),
//     <dir>/<category>/manifest.json, with their binaries in <category>/bin;
//   - without a build-time inventory (a native or development run), the
//     well-known tools found on PATH.

const (
	toolInventoryEnv = "ARTEX_TOOL_INVENTORY"
	toolboxDirEnv    = "ARTEX_TOOLBOX_DIR"
	defaultToolbox   = "/opt/toolbox"
)

// toolEntry is one tool of an inventory file, and of the list_tools answer.
type toolEntry struct {
	Name    string   `json:"name"`
	Version string   `json:"version,omitempty"`
	Path    string   `json:"path,omitempty"`
	Package string   `json:"package,omitempty"`
	Tags    []string `json:"tags,omitempty"`
	Source  string   `json:"source,omitempty"`
	Note    string   `json:"note,omitempty"`
}

// toolInventory is the shape of the build-time inventory and of a toolbox
// manifest. BaseVersion is the ARTEX image a toolbox was built against.
type toolInventory struct {
	Category    string      `json:"category,omitempty"`
	BaseVersion string      `json:"base_version,omitempty"`
	Tools       []toolEntry `json:"tools"`
}

// knownToolTags tags the well-known tools: it annotates inventory entries
// that carry no tags, and names the tools the PATH fallback looks for.
var knownToolTags = map[string][]string{
	"nuclei": {"web", "vuln-scan"}, "nuclei-templates": {"web", "vuln-scan", "data"},
	"httpx": {"web", "recon"}, "katana": {"web", "crawl"}, "ffuf": {"web", "fuzz"},
	"dalfox": {"web", "xss"}, "sqlmap": {"web", "sqli"}, "gobuster": {"web", "fuzz"},
	"feroxbuster": {"web", "fuzz"}, "wfuzz": {"web", "fuzz"}, "whatweb": {"web", "fingerprint"},
	"wafw00f": {"web", "fingerprint"}, "nikto": {"web", "vuln-scan"}, "arjun": {"web", "params"},
	"subfinder": {"recon", "dns"}, "dnsx": {"recon", "dns"}, "amass": {"recon", "dns"},
	"bbot": {"recon"}, "nmap": {"recon", "network"}, "masscan": {"recon", "network"},
	"naabu": {"recon", "network"}, "fping": {"recon", "network"}, "arp-scan": {"recon", "network"},
	"netdiscover": {"recon", "network"}, "whois": {"recon"}, "dig": {"recon", "dns"},
	"hydra": {"brute"}, "ncrack": {"brute"}, "john": {"brute", "cracking"}, "hashcat": {"brute", "cracking"},
	"netexec": {"ad", "windows"}, "nxc": {"ad", "windows"}, "kerbrute": {"ad", "windows"},
	"smbclient": {"ad", "windows", "smb"}, "rpcclient": {"ad", "windows", "smb"}, "smbcacls": {"ad", "windows", "smb"},
	"nmblookup": {"ad", "windows", "smb"}, "enum4linux-ng": {"ad", "windows", "smb", "recon"},
	"ldapsearch": {"ad", "windows", "ldap"}, "evil-winrm": {"ad", "windows"},
	// Debian's python3-impacket installs these five; psexec, GetUserSPNs,
	// ntlmrelayx etc. come with a toolbox (artex-tools-ad), not the base image.
	"impacket-secretsdump": {"ad", "windows"}, "impacket-wmiexec": {"ad", "windows"},
	"impacket-rpcdump": {"ad", "windows"}, "impacket-samrdump": {"ad", "windows"},
	"impacket-netview": {"ad", "windows"},
	"ssh-audit":        {"network", "ssh"}, "sshpass": {"network", "ssh"}, "nc": {"network"},
	"socat": {"network"}, "telnet": {"network"}, "scapy": {"network"}, "openssl": {"crypto"},
	"curl": {"http"}, "wget": {"http"}, "git": {"vcs"}, "jq": {"util"},
	"python3": {"runtime"}, "node": {"runtime"}, "playwright-cli": {"browser"}, "chromium": {"browser"},
	"gdb": {"binary"}, "checksec": {"binary"}, "ROPgadget": {"binary"},
}

func toolInventoryPath() string {
	if p := strings.TrimSpace(os.Getenv(toolInventoryEnv)); p != "" {
		return p
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "tool-inventory.json")
}

func toolboxDir() string {
	if d := strings.TrimSpace(os.Getenv(toolboxDirEnv)); d != "" {
		return d
	}
	return defaultToolbox
}

// InstalledToolVersion returns the version the build-time tool inventory
// records for a tool (e.g. "v10.5.1 (<commit>)" for nuclei-templates), or ""
// when there is no inventory (a native run) or no such tool.
func InstalledToolVersion(name string) string {
	inv, err := readInventory(toolInventoryPath())
	if err != nil {
		return ""
	}
	for _, e := range inv.Tools {
		if e.Name == name {
			return e.Version
		}
	}
	return ""
}

func readInventory(path string) (*toolInventory, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var inv toolInventory
	if err := json.Unmarshal(b, &inv); err != nil {
		return nil, err
	}
	return &inv, nil
}

// locate returns where a tool is: its declared path when that file exists
// (resolved against dir when relative), else the PATH lookup of its name.
func locate(e toolEntry, dir string) (string, bool) {
	if e.Path != "" {
		p := e.Path
		if !filepath.IsAbs(p) && dir != "" {
			p = filepath.Join(dir, p)
		}
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
		return p, false
	}
	if p, err := exec.LookPath(e.Name); err == nil {
		return p, true
	}
	return "", false
}

// collectTools gathers the inventory. missing lists the tools a manifest names
// that are not on disk, so a broken image or toolbox is visible instead of
// silently shrinking the list.
func collectTools() (tools []toolEntry, missing []string) {
	add := func(e toolEntry, dir, source string) {
		p, ok := locate(e, dir)
		if !ok {
			missing = append(missing, e.Name)
			return
		}
		e.Path, e.Source = p, source
		if len(e.Tags) == 0 {
			e.Tags = knownToolTags[e.Name]
		}
		tools = append(tools, e)
	}

	base := ""
	if inv, err := readInventory(toolInventoryPath()); err == nil {
		base = inv.BaseVersion
		for _, e := range inv.Tools {
			add(e, "", "image")
		}
	} else {
		// No build-time inventory: report the well-known tools found on PATH.
		names := make([]string, 0, len(knownToolTags))
		for n := range knownToolTags {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			if p, err := exec.LookPath(n); err == nil {
				tools = append(tools, toolEntry{Name: n, Path: p, Tags: knownToolTags[n], Source: "path"})
			}
		}
	}

	manifests, _ := filepath.Glob(filepath.Join(toolboxDir(), "*", "manifest.json"))
	slices.Sort(manifests)
	for _, m := range manifests {
		inv, err := readInventory(m)
		if err != nil {
			continue
		}
		dir := filepath.Dir(m)
		category := inv.Category
		if category == "" {
			category = filepath.Base(dir)
		}
		note := ""
		if inv.BaseVersion != "" && base != "" && inv.BaseVersion != base {
			note = "toolbox built for ARTEX image " + inv.BaseVersion + ", this image is " + base + ": it may not run"
		}
		for _, e := range inv.Tools {
			if e.Path == "" {
				e.Path = filepath.Join("bin", e.Name)
			}
			if len(e.Tags) == 0 {
				e.Tags = []string{category}
			}
			if note != "" {
				e.Note = note
			}
			add(e, dir, "toolbox:"+category)
		}
	}
	return tools, missing
}

func (t *ToolSet) listTools() actool.CoreTool {
	return readTool(
		"list_tools",
		"List the command-line tools installed for you to run (name, version, path, tags such as web, recon, ad, brute), "+
			"from the image's build manifest and any installed toolboxes. Check here before planning a step around a tool, "+
			"and pick an installed alternative instead of downloading or installing one: in offline mode there is no network "+
			"and installs are refused. Optional filters: search (substring of the name or a tag) and tag (exact tag).",
		obj(map[string]any{
			"search": str("substring of the tool name or of one of its tags (optional)"),
			"tag":    str("exact tag, e.g. web, recon, ad, brute, network (optional)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Search string `json:"search"`
				Tag    string `json:"tag"`
			}
			_ = json.Unmarshal(in, &a)
			q := strings.ToLower(strings.TrimSpace(a.Search))
			tag := strings.ToLower(strings.TrimSpace(a.Tag))
			all, missing := collectTools()
			out := make([]toolEntry, 0, len(all))
			for _, e := range all {
				if tag != "" && !slices.ContainsFunc(e.Tags, func(s string) bool { return strings.EqualFold(s, tag) }) {
					continue
				}
				if q != "" && !strings.Contains(strings.ToLower(e.Name), q) &&
					!slices.ContainsFunc(e.Tags, func(s string) bool { return strings.Contains(strings.ToLower(s), q) }) {
					continue
				}
				out = append(out, e)
			}
			res := map[string]any{"count": len(out), "tools": out}
			if len(missing) > 0 {
				res["missing"] = missing
			}
			return jsonResult(res)
		},
	)
}
