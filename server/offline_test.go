package server

import (
	"net/netip"
	"strings"
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

// In offline mode the http tool's own proxy is refused (any proxy, LAN ones
// included, forwards to any destination); the transport fails every dial with
// an offline refusal instead of contacting the proxy.
func TestHTTPToolProxyRefusedOffline(t *testing.T) {
	t.Setenv("ARTEX_OFFLINE", "1")
	s := &Server{}
	for _, p := range []string{"http://10.0.0.5:3128", "http://127.0.0.1:8080"} {
		tr := s.httpProxyTransport(httpExec{Proxy: p})
		if tr == nil || tr.DialContext == nil {
			t.Fatalf("%s: want a refusing transport, got %#v", p, tr)
		}
		if tr.Proxy != nil {
			t.Errorf("%s: the refusing transport must not use the proxy", p)
		}
		if _, err := tr.DialContext(t.Context(), "tcp", "10.0.0.5:3128"); err == nil || !strings.Contains(err.Error(), "offline mode") {
			t.Errorf("%s: dial must be refused with an offline message, got %v", p, err)
		}
	}
	t.Setenv("ARTEX_OFFLINE", "0")
	if tr := s.httpProxyTransport(httpExec{Proxy: "http://10.0.0.5:3128"}); tr == nil || tr.Proxy == nil {
		t.Error("offline off: the per-tool proxy must be used as before")
	}
}
