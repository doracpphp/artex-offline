package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEgressFirewallStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress-firewall")
	t.Setenv(egressFirewallStatusEnv, path)
	t.Setenv(egressFirewallExternalEnv, "")

	// Offline off: nothing to report, whatever the file says.
	t.Setenv("ARTEX_OFFLINE", "0")
	if _, ok := egressFirewallStatus(); ok {
		t.Fatal("offline off: the firewall state must not be reported")
	}

	t.Setenv("ARTEX_OFFLINE", "1")
	// No status file while offline: reported as absent (banner).
	if st, ok := egressFirewallStatus(); !ok || st.Mode != "absent" || st.Reason == "" {
		t.Fatalf("no status file offline: got %+v (%v), want absent with a reason", st, ok)
	}
	// The operator declares an external boundary.
	t.Setenv(egressFirewallExternalEnv, "1")
	if st, ok := egressFirewallStatus(); !ok || st.Mode != "external" {
		t.Fatalf("external declared: got %+v (%v)", st, ok)
	}
	t.Setenv(egressFirewallExternalEnv, "")

	for body, want := range map[string]EgressFirewallStatus{
		"enforced\n": {Mode: "enforced"},
		"failed: could not apply the IPv4 rules (is NET_ADMIN granted?)\n": {Mode: "degraded", Reason: "could not apply the IPv4 rules (is NET_ADMIN granted?)"},
		"garbage": {Mode: "degraded", Reason: "garbage"},
	} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		got, ok := egressFirewallStatus()
		if !ok || got != want {
			t.Errorf("%q: got %+v (%v), want %+v", body, got, ok, want)
		}
	}
}
