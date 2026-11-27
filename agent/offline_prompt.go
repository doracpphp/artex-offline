package agent

import "github.com/doracpphp/artex-offline/offline"

// offlinePromptBlock is the code-owned prompt block of offline mode
// (docs/offline-toolbox.md §6.1). It is appended after the editable body, like
// the untrusted-content block, so that a DB prompt override or an operator edit
// cannot drop it. It tells the model up front what the egress gates and the
// install refusal would otherwise teach it one failed turn at a time.
const offlinePromptBlock = `

[Offline mode. Operator setting, not a target fact.]
This deployment has no external network: only local and LAN addresses are reachable. Downloads and installs from the internet (apt, pip, npm, go install, git clone or curl/wget from public hosts) fail and are refused by the platform.
- Plan with the tools that are installed: run list_tools if you have it, otherwise check a single tool with ` + "`command -v <tool>`" + `.
- When a tool you want is missing, use an installed alternative or a manual technique; do not look for another way to download it.
`

// knowledgePromptLine is appended when a knowledge pack is active: the local
// search tools are the substitute for the web lookups the model would otherwise
// reach for (docs/offline-knowledge-search.md §4.4).
const knowledgePromptLine = "- To look something up — an exploit, a CVE, a product's known vulnerabilities, an attack technique — use the local knowledge tools (search_exploits, lookup_cve, lookup_software, search_technique, read_knowledge), not the web. Cite the source they return in any finding.\n"

// offlineBlock returns the offline-mode prompt block, plus the knowledge line
// when a pack is active. It returns "" only when offline mode is off and no
// knowledge pack is available.
func offlineBlock() string {
	block := ""
	if offline.Enabled() {
		block = offlinePromptBlock
	}
	if KnowledgeAvailable() {
		if block == "" {
			block = "\n"
		}
		block += knowledgePromptLine
	}
	return block
}
