package server

import (
	"log"
	"os"
	"strings"

	"github.com/doracpphp/artex-offline/offline"
)

// Egress firewall of offline mode (docs/offline-toolbox.md §6.4). docker-compose
// enables it by default: start.sh runs offline-firewall.sh as root before artex
// starts and records the outcome in a status file the executor cannot write.
// The server only reads it, to report the state in GET /api/health (the web UI
// shows anything but "enforced" / "external" as a banner on every page) and in
// the startup log.

const (
	egressFirewallStatusEnv     = "ARTEX_EGRESS_FIREWALL_STATUS"
	defaultEgressFirewallStatus = "/run/artex/egress-firewall"
	// egressFirewallExternalEnv lets an operator who enforces egress outside the
	// container (a host firewall, an air-gapped host, a locked-down network
	// namespace) say so, which silences the "no firewall" banner. ARTEX cannot
	// verify the claim; it is reported as "external", not "enforced".
	egressFirewallExternalEnv = "ARTEX_EGRESS_FIREWALL_EXTERNAL"
)

// EgressFirewallStatus is the egress firewall state reported by GET /api/health.
type EgressFirewallStatus struct {
	// "enforced": the in-container firewall is applied.
	// "external": no in-container firewall; the operator declared an external one.
	// "absent":   no firewall in this container (native run, or the compose
	//             default turned off) — tools that ignore the proxy variables
	//             can reach whatever the host routes to.
	// "degraded": the firewall was requested but could not be applied.
	Mode   string `json:"mode"`
	Reason string `json:"reason,omitempty"`
}

// egressFirewallStatus returns the state to report. ok is false when there is
// nothing to report: offline mode is off (online targets can be anywhere).
func egressFirewallStatus() (st EgressFirewallStatus, ok bool) {
	if !offline.Enabled() {
		return EgressFirewallStatus{}, false
	}
	path := strings.TrimSpace(os.Getenv(egressFirewallStatusEnv))
	if path == "" {
		path = defaultEgressFirewallStatus
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if isTruthy(os.Getenv(egressFirewallExternalEnv)) {
			return EgressFirewallStatus{Mode: "external", Reason: egressFirewallExternalEnv + " is set: egress is enforced outside this container"}, true
		}
		return EgressFirewallStatus{Mode: "absent", Reason: "no egress firewall in this container: tools that ignore the proxy variables can reach any network the host routes to. Run with docker compose (the firewall is on by default), or enforce egress on the host and set " + egressFirewallExternalEnv + "=1"}, true
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

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

// logOfflineState writes the startup lines of offline mode: the mode itself,
// invalid allow-list entries (otherwise silently ignored) and the firewall state.
func logOfflineState() {
	if !offline.Enabled() {
		return
	}
	log.Printf("[offline] offline / local-LLM-only mode is ON: only local LLM endpoints are usable; ARTEX's own third-party connections (cloud LLM, update check, external notifications, web search, remote MCP, cloud archive, egress proxies) are refused, and agent connections through ARTEX reach local or %s addresses only. Tools in agent shells that connect directly are stopped only by the egress firewall. Set %s=0 to disable.", offline.AllowCIDRsEnv, offline.Env)
	if prefixes, invalid := offline.AllowCIDRs(); len(invalid) > 0 {
		log.Printf("[offline] %s: ignored invalid entries %q", offline.AllowCIDRsEnv, invalid)
	} else if len(prefixes) > 0 {
		log.Printf("[offline] %s: also treating %v as local", offline.AllowCIDRsEnv, prefixes)
	}
	if !offline.DenyInstalls() {
		log.Printf("[offline] %s=0: package installs in agent shells are not refused", offline.DenyInstallsEnv)
	}
	st, _ := egressFirewallStatus()
	switch st.Mode {
	case "enforced":
		log.Printf("[offline] egress firewall enforced: this container reaches local and allow-listed ranges only")
	case "external":
		log.Printf("[offline] egress firewall: %s", st.Reason)
	case "absent":
		log.Printf("[offline] WARNING: %s", st.Reason)
	default:
		log.Printf("[offline] WARNING: egress firewall degraded: %s", st.Reason)
	}
}
