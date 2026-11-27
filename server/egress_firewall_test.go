package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEgressFirewallStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress-firewall")
	t.Setenv(egressFirewallStatusEnv, path)
	if _, ok := egressFirewallStatus(); ok {
		t.Fatal("no status file: the firewall was not requested, nothing to report")
	}
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
