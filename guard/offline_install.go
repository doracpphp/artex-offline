package guard

import (
	"regexp"
	"strings"

	"github.com/Autumn-27/artex/offline"
)

// Offline refusal of package installs (docs/offline-toolbox.md §6.2).
//
// In offline mode an install cannot succeed (no network), so the agent is told
// so at once, with the way forward, instead of spending turns on retries and
// other download routes. The check is code-owned rather than an opt-in rule:
// it cannot be forgotten, and it applies to the target-only guard (planner,
// main agent) as well. Like the "[hardening] Package installation" rule it
// mirrors, it is a tripwire on the command line with known bypasses, not a
// boundary — network isolation is (§6.4). ARTEX_DENY_INSTALLS=0 turns it off,
// e.g. when a local package mirror serves the installs.

// offlineInstallRe matches the package-install command forms of the hardening
// rule on the decoded command line, plus dnf/yum/apk. "go install" is matched
// only with a remote version (pkg@version): building a local path is not an
// install from the network.
var offlineInstallRe = regexp.MustCompile(`(?i)(?:` +
	`\b(?:pip[0-9.]*|pipx|uv\s+pip|uv\s+tool|python[0-9.]*\s+-m\s+pip)\s+install\b` +
	`|\bnpm\s+(?:i|install|exec)\b|\bnpx\s|\bpnpm\s+(?:add|install|dlx)\b|\byarn\s+(?:add|dlx)\b` +
	`|\bgo\s+get\b|\bgo\s+install\s+(?:-\S+\s+)*\S*@` +
	`|\bgem\s+install\b|\bcargo\s+install\b|\bcomposer\s+(?:require|create-project|global)\b` +
	`|\bapt(?:-get)?\s+(?:-\S+\s+)*install\b|\b(?:dnf|yum)\s+(?:-\S+\s+)*install\b|\bapk\s+(?:-\S+\s+)*add\b` +
	`)`)

// offlineInstallExempt marks an install the operator made explicitly local:
// pip's --no-index (wheels on disk) or a package manager's --offline mode.
var offlineInstallExempt = regexp.MustCompile(`(?:^|\s)--(?:no-index|offline)\b`)

// offlineInstallMessage is the reason the model reads in the block message.
const offlineInstallMessage = "offline mode: installing packages is not possible here, there is no external network. " + offline.Hint

// offlineInstallBlock reports whether cmd (the shell command of a Bash /
// shell_open / shell_send call) is a package install that offline mode refuses.
func offlineInstallBlock(cmd string) bool {
	if cmd == "" || !offline.DenyInstalls() {
		return false
	}
	if !offlineInstallRe.MatchString(cmd) {
		return false
	}
	return !offlineInstallExempt.MatchString(strings.ToLower(cmd))
}
