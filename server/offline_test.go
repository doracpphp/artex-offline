package server

import (
	"net/netip"
	"testing"
)

func TestUpdateCheckForcedOffWhenOffline(t *testing.T) {
	// Even with the opt-in explicitly on, offline mode forces the GitHub release
	// check off so no request reaches a third party.
	t.Setenv("ARTEX_UPDATE_CHECK", "1")
	t.Setenv("ARTEX_OFFLINE", "1")
	if updateCheckEnabled() {
		t.Fatal("offline mode must force the update check off")
	}
	t.Setenv("ARTEX_OFFLINE", "0")
	if !updateCheckEnabled() {
		t.Fatal("with offline off and opt-in on, the update check must be enabled")
	}
}

func TestIsBlockedModelAddrOfflineInversion(t *testing.T) {
	s := &Server{}
	t.Setenv("ARTEX_OFFLINE", "1")

	// Offline: only local (loopback / private) endpoints may be listed; the
	// allowPrivate argument is irrelevant because offline forces local-only.
	allowed := []string{"127.0.0.1", "::1", "10.0.0.5", "192.168.1.1", "172.16.0.9", "fd00::1"}
	for _, s4 := range allowed {
		addr := netip.MustParseAddr(s4)
		if s.isBlockedModelAddr(addr, false) {
			t.Errorf("offline: local model host %s must be allowed", s4)
		}
	}
	blocked := []string{"8.8.8.8", "1.1.1.1", "169.254.169.254", "fe80::1", "2606:4700:4700::1111"}
	for _, s4 := range blocked {
		addr := netip.MustParseAddr(s4)
		if !s.isBlockedModelAddr(addr, true) {
			t.Errorf("offline: non-local model host %s must be refused even with allowPrivate", s4)
		}
	}
}
