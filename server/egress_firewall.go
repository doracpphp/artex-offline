package server

import (
	"log"
	"os"
	"strings"

	"github.com/Autumn-27/artex/offline"
)

// Egress firewall of the offline compose overlay (docs/offline-toolbox.md §6.4).
// start.sh runs offline-firewall.sh as root before artex starts, when
// ARTEX_OFFLINE_FIREWALL is on, and records the outcome in a status file the
// executor cannot write. The server only reads it, to report the state in
// GET /api/health (the web UI shows a degraded firewall as a banner) and in the
// startup log. Without the overlay there is no status file and nothing is
// reported: egress is then the operator's network, not ARTEX's.

const (
	egressFirewallStatusEnv     = "ARTEX_EGRESS_FIREWALL_STATUS"
	defaultEgressFirewallStatus = "/run/artex/egress-firewall"
)

// EgressFirewallStatus is the egress firewall state reported by GET /api/health.
type EgressFirewallStatus struct {
	Mode   string `json:"mode"` // "enforced" | "degraded"
	Reason string `json:"reason,omitempty"`
}

// egressFirewallStatus reads the status file. ok is false when the firewall
// was not requested (no file).
func egressFirewallStatus() (st EgressFirewallStatus, ok bool) {
	path := strings.TrimSpace(os.Getenv(egressFirewallStatusEnv))
	if path == "" {
		path = defaultEgressFirewallStatus
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return EgressFirewallStatus{}, false
	}
	line := strings.TrimSpace(string(b))
	if line == "enforced" {
		return EgressFirewallStatus{Mode: "enforced"}, true
	}
	reason := strings.TrimSpace(strings.TrimPrefix(line, "failed:"))
	if reason == "" {
		reason = "unknown state " + line
	}
	return EgressFirewallStatus{Mode: "degraded", Reason: reason}, true
}

// logOfflineState writes the startup lines of offline mode: the mode itself,
// invalid allow-list entries (otherwise silently ignored) and the firewall state.
func logOfflineState() {
	if !offline.Enabled() {
		return
	}
	log.Printf("[offline] offline / local-LLM-only mode is ON: only local LLM endpoints are usable; third-party egress (cloud LLM, update check, external notifications, web search, remote MCP, cloud archive) is blocked, and agent connections without a target gate reach local addresses only. Set %s=0 to disable.", offline.Env)
	if prefixes, invalid := offline.AllowCIDRs(); len(invalid) > 0 {
		log.Printf("[offline] %s: ignored invalid entries %q", offline.AllowCIDRsEnv, invalid)
	} else if len(prefixes) > 0 {
		log.Printf("[offline] %s: also treating %v as local", offline.AllowCIDRsEnv, prefixes)
	}
	if !offline.DenyInstalls() {
		log.Printf("[offline] %s=0: package installs in agent shells are not refused", offline.DenyInstallsEnv)
	}
	switch st, ok := egressFirewallStatus(); {
	case !ok:
		log.Printf("[offline] no egress firewall in this container: tools that ignore the proxy variables can still reach any network the host routes to (see docker-compose.offline.yml)")
	case st.Mode == "enforced":
		log.Printf("[offline] egress firewall enforced: this container reaches local ranges only")
	default:
		log.Printf("[offline] WARNING: egress firewall degraded: %s", st.Reason)
	}
}
